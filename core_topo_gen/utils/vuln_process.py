from __future__ import annotations
import copy
import logging
import os
import csv
import json
import random
import re
from typing import Iterable, Tuple, List, Dict, Optional, Set
import urllib.request
import shutil
import sys
import select

try:
	import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency handled at runtime
	yaml = None  # type: ignore


logger = logging.getLogger(__name__)

_COMPOSE_PORT_CACHE: Dict[Tuple[str, str], List[Dict[str, object]]] = {}


_DOCKER_SUDO_PASSWORD_CACHE: Optional[str] = None


def _docker_sudo_password() -> Optional[str]:
	"""Return sudo password for docker commands, if configured.

	Supports:
	- `CORETG_DOCKER_SUDO_PASSWORD`: explicit password
	- `CORETG_DOCKER_SUDO_PASSWORD_STDIN=1`: read one line from stdin once
	"""
	global _DOCKER_SUDO_PASSWORD_CACHE
	if _DOCKER_SUDO_PASSWORD_CACHE is not None:
		return _DOCKER_SUDO_PASSWORD_CACHE or None
	try:
		pw = os.getenv('CORETG_DOCKER_SUDO_PASSWORD')
		if pw is not None and str(pw).strip() != '':
			_DOCKER_SUDO_PASSWORD_CACHE = str(pw).rstrip('\n')
			return _DOCKER_SUDO_PASSWORD_CACHE
	except Exception:
		pass
	try:
		flag = os.getenv('CORETG_DOCKER_SUDO_PASSWORD_STDIN')
		if flag is not None and str(flag).strip().lower() in ('1', 'true', 'yes', 'y', 'on'):
			# Avoid hanging indefinitely if stdin is not connected (common in remote exec).
			line = ''
			try:
				r, _w, _x = select.select([sys.stdin], [], [], 2.0)
				if r:
					line = sys.stdin.readline()
				else:
					return None
			except Exception:
				return None
			pw2 = (line or '').rstrip('\n')
			if pw2.strip() != '':
				_DOCKER_SUDO_PASSWORD_CACHE = pw2
				try:
					os.environ['CORETG_DOCKER_SUDO_PASSWORD'] = pw2
				except Exception:
					pass
				return _DOCKER_SUDO_PASSWORD_CACHE
			_DOCKER_SUDO_PASSWORD_CACHE = ''
			return None
	except Exception:
		pass
	_DOCKER_SUDO_PASSWORD_CACHE = ''
	return None


def _discover_flow_artifacts_dir(scenario_tag: str = '', node_name: str = '', out_base: str = '/tmp/vulns') -> Optional[str]:
	"""Discover the latest flow artifacts directory when ArtifactsDir is missing.

	Scans /tmp/vulns/flag_generators_runs/ and /tmp/vulns/flag_node_generators_runs/
	for the most recent flow run directory, optionally filtered by scenario_tag.

	This is a fallback for when loading from saved XML where artifacts_dir was not persisted.
	"""
	try:
		search_dirs = [
			os.path.join(out_base, 'flag_generators_runs'),
			os.path.join(out_base, 'flag_node_generators_runs'),
			'/tmp/vulns/flag_generators_runs',
			'/tmp/vulns/flag_node_generators_runs',
		]
		candidates: List[str] = []
		scenario_norm = re.sub(r'[^a-zA-Z0-9_-]', '_', str(scenario_tag or '').strip().lower()) if scenario_tag else ''
		for base_dir in search_dirs:
			if not os.path.isdir(base_dir):
				continue
			try:
				for entry in os.scandir(base_dir):
					if not entry.is_dir():
						continue
					# Match flow-{scenario}-{uuid} pattern
					if entry.name.startswith('flow-'):
						# If scenario_tag provided, filter by it
						if scenario_norm and scenario_norm not in entry.name.lower():
							continue
						candidates.append(entry.path)
			except Exception:
				continue

		if not candidates:
			return None

		# Sort by modification time descending (most recent first)
		candidates.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)

		# Prefer directories with 'artifacts' subdirectory
		for cand in candidates:
			artifacts_sub = os.path.join(cand, 'artifacts')
			if os.path.isdir(artifacts_sub):
				logger.debug('[vuln] discovered flow artifacts dir: %s', artifacts_sub)
				return artifacts_sub

		# Fall back to most recent run directory directly
		if candidates:
			logger.debug('[vuln] discovered flow run dir (no artifacts subdir): %s', candidates[0])
			return candidates[0]

		return None
	except Exception as exc:
		logger.debug('[vuln] _discover_flow_artifacts_dir failed: %s', exc)
		return None


def _read_csv(path: str) -> List[Dict[str, str]]:
	rows: List[Dict[str, str]] = []
	def _get(row: Dict[str, str], key: str) -> str:
		try:
			v = row.get(key)
			if v is not None:
				return v
		except Exception:
			pass
		# Handle BOM-prefixed header names seen in some CSV exports.
		try:
			if not key.startswith('\ufeff'):
				v2 = row.get('\ufeff' + key)
				if v2 is not None:
					return v2
		except Exception:
			pass
		return ''

	try:
		with open(path, newline='', encoding='utf-8', errors='ignore') as f:
			r = csv.DictReader(f)
			for row in r:
				# Normalize keys we care about; ignore rows without mandatory fields
				name = (_get(row, 'Name') or '').strip()
				path_val = (_get(row, 'Path') or '').strip()
				if not name or not path_val:
					continue
				rows.append({
					'Name': name,
					'Path': path_val,
					'Type': (_get(row, 'Type') or '').strip(),
					'Vector': (_get(row, 'Vector') or '').strip(),
					'Startup': (_get(row, 'Startup') or '').strip(),
					'CVE': (_get(row, 'CVE') or '').strip(),
					'Description': (_get(row, 'Description') or '').strip(),
					'References': (_get(row, 'References') or '').strip(),
				})
	except Exception:
		return []
	return rows


def load_vuln_catalog(repo_root: str) -> List[Dict[str, str]]:
	"""Load a vulnerability catalog for CLI selection.

	Best-effort: prefer an "active" installed catalog (written by the Web UI) and
	fall back to raw_datasources CSVs shipped with the repo.
	Returns a list of dicts with at least Name, Path, and optional Type/Vector.
	"""
	def _normalize_catalog_path(root: str, raw_path: str) -> str:
		p = (raw_path or '').strip()
		if not p:
			return p
		# Preserve URLs as-is.
		try:
			if re.match(r'^https?://', p, re.IGNORECASE):
				return p
		except Exception:
			pass
		# Relative paths resolve against repo root.
		if not os.path.isabs(p):
			try:
				return os.path.abspath(os.path.join(root, p))
			except Exception:
				return p
		# Absolute path exists: keep it.
		try:
			if os.path.exists(p):
				return p
		except Exception:
			pass
		# Remap installed catalog absolute paths from another machine.
		try:
			norm = p.replace('\\', '/')
			marker = '/outputs/installed_vuln_catalogs/'
			if marker in norm:
				suffix = norm.split(marker, 1)[1]
				candidate = os.path.join(root, 'outputs', 'installed_vuln_catalogs', suffix)
				return os.path.abspath(candidate)
		except Exception:
			pass
		return p
	def _installed_state_path(root: str) -> str:
		return os.path.join(root, 'outputs', 'installed_vuln_catalogs', '_catalogs_state.json')

	def _load_installed_state(root: str) -> Dict[str, object]:
		try:
			p = _installed_state_path(root)
			if not os.path.exists(p):
				return {}
			with open(p, 'r', encoding='utf-8') as f:
				obj = json.load(f)
			return obj if isinstance(obj, dict) else {}
		except Exception:
			return {}

	def _active_installed_csvs(root: str) -> List[str]:
		state = _load_installed_state(root)
		active_id = str(state.get('active_id') or '').strip() if isinstance(state, dict) else ''
		catalogs = state.get('catalogs') if isinstance(state, dict) else None
		if not active_id or not isinstance(catalogs, list):
			return []
		for c in catalogs:
			if not isinstance(c, dict):
				continue
			cid = str(c.get('id') or '').strip()
			if cid != active_id:
				continue
			paths = c.get('csv_paths')
			out: List[str] = []
			if isinstance(paths, list):
				for p in paths:
					ps = str(p or '').strip()
					if not ps:
						continue
					# Allow relative paths in state for portability.
					if not os.path.isabs(ps):
						ps = os.path.join(root, ps)
					out.append(ps)
				return out
			# Back-compat: a single csv_path string
			ps2 = str(c.get('csv_path') or '').strip()
			if ps2:
				if not os.path.isabs(ps2):
					ps2 = os.path.join(root, ps2)
				return [ps2]
			return []
		return []

	active_csvs = list(_active_installed_csvs(repo_root) or [])
	items: List[Dict[str, str]] = []

	# 1) Active installed catalog (if present). Important behavior: if the active
	# installed catalog exists but contains zero rows, treat the catalog as empty
	# (do NOT fall back to repo defaults). This matches the Web UI expectation
	# that deleting all items results in no selectable vulnerabilities.
	active_any_exists = False
	for p in active_csvs:
		if os.path.exists(p):
			active_any_exists = True
			items.extend(_read_csv(p))
	if active_csvs and active_any_exists and not items:
		return []

	# 2) Repo-shipped defaults (only when no active installed catalog is present,
	# or when active paths are missing entirely).
	for p in [
		os.path.join(repo_root, 'raw_datasources', 'vuln_list_w_url.csv'),
		os.path.join(repo_root, 'raw_datasources', 'vuln_list.csv'),
	]:
		if os.path.exists(p):
			items.extend(_read_csv(p))
	# Normalize Path entries for portability between local GUI and remote CORE host.
	try:
		for it in items:
			try:
				path_val = it.get('Path') if isinstance(it, dict) else None
				if path_val:
					it['Path'] = _normalize_catalog_path(repo_root, str(path_val))
			except Exception:
				continue
	except Exception:
		pass
	# Deduplicate by (Name, Path)
	seen = set()
	out: List[Dict[str, str]] = []
	for it in items:
		key = (it.get('Name'), it.get('Path'))
		if key in seen:
			continue
		seen.add(key)
		out.append(it)
	return out


def _norm_type(s: str) -> str:
	s = (s or '').strip().lower()
	if s in ("docker", "compose", "docker compose", "docker-compose", "docker_compose"):
		return "docker-compose"
	return s


def _filter_by_type_vector(catalog: Iterable[Dict[str, str]], v_type: str | None, v_vector: str | None) -> List[Dict[str, str]]:
	vt = _norm_type(v_type or '')
	vv = (v_vector or '').strip().lower()
	out: List[Dict[str, str]] = []
	for it in catalog:
		it_vt = _norm_type(it.get('Type') or '')
		it_vv = (it.get('Vector') or '').strip().lower()
		if vt and it_vt != vt:
			continue
		if vv and it_vv != vv:
			continue
		out.append(it)
	return out


def select_vulnerabilities(density: float, items_cfg: List[dict], catalog: List[Dict[str, str]]) -> List[Dict[str, str]]:
	"""Select vulnerabilities from catalog based on density and config items.

	- density in [0..1] scales the total number of selections.
	- items_cfg is a list of entries with 'selected' and optional fields:
	  * 'Random': use entire catalog
	  * 'Type/Vector': filter by keys 'v_type' and 'v_vector'
	  * 'Specific': use provided 'v_name' and 'v_path'
	"""
	# Even if catalog is empty, we can still honor 'Specific' selections by returning them directly
	dens = max(0.0, min(1.0, float(density or 0.0)))
	total_target = int(round(dens * len(catalog))) if catalog else 0
	if dens > 0.0 and total_target == 0 and len(catalog) > 0:
		total_target = 1
	# Determine per-item allocations based on factors
	factors: List[float] = []
	s_items = items_cfg or []
	if s_items:
		total_factor = 0.0
		for it in s_items:
			try:
				total_factor += float(it.get('factor') or 0.0)
			except Exception:
				continue
		if total_factor <= 0:
			factors = [1.0 / len(s_items) for _ in s_items]
		else:
			factors = [max(0.0, float((it.get('factor') or 0.0))) / total_factor for it in s_items]
	else:
		s_items = [{'selected': 'Random', 'factor': 1.0}]
		factors = [1.0]

	selected: List[Dict[str, str]] = []
	used = set()
	remaining = total_target
	for it, frac in zip(s_items, factors):
		sel = (it.get('selected') or 'Random').strip()
		# Accept UI synonym 'Category' for 'Type/Vector'
		if sel == 'Category':
			sel = 'Type/Vector'
		# Specific selections bypass density allocation and are always included
		if sel == 'Specific':
			name = (it.get('v_name') or '').strip()
			path = (it.get('v_path') or '').strip()
			if name and path:
				key = (name, path)
				if key not in used:
					selected.append({'Name': name, 'Path': path})
					used.add(key)
			continue
		# Determine candidate pool
		pool = catalog
		if sel == 'Type/Vector':
			pool = _filter_by_type_vector(catalog, it.get('v_type'), it.get('v_vector'))
		# Allocate count
		alloc = int(round(frac * total_target)) if total_target > 0 else 0
		alloc = min(max(0, alloc), max(0, remaining))
		if alloc <= 0:
			continue
		# Random sample without replacement respecting already used items
		pool2 = [p for p in pool if (p.get('Name'), p.get('Path')) not in used] if pool else []
		if not pool2:
			continue
		if alloc >= len(pool2):
			picks = pool2
		else:
			picks = random.sample(pool2, alloc)
		for p in picks:
			key = (p.get('Name'), p.get('Path'))
			if key in used:
				continue
			used.add(key)
			selected.append(p)
		remaining = max(0, remaining - len(picks))
		if remaining <= 0:
			break
	return selected


# ---------------- docker-compose assignment helpers ----------------

def _parse_github_url(url: str) -> dict:
	try:
		from urllib.parse import urlparse
		u = urlparse(url)
		if u.netloc.lower() != 'github.com':
			return {'is_github': False}
		parts = [p for p in u.path.strip('/').split('/') if p]
		if len(parts) < 2:
			return {'is_github': False}
		owner, repo = parts[0], parts[1]
		git_url = f"https://github.com/{owner}/{repo}.git"
		if len(parts) == 2:
			return {'is_github': True, 'git_url': git_url, 'branch': None, 'subpath': '', 'mode': 'root'}
		mode = parts[2]
		if mode not in ('tree', 'blob') or len(parts) < 4:
			return {'is_github': True, 'git_url': git_url, 'branch': None, 'subpath': '', 'mode': 'root'}
		branch = parts[3]
		rest = '/'.join(parts[4:])
		return {'is_github': True, 'git_url': git_url, 'branch': branch, 'subpath': rest, 'mode': mode}
	except Exception:
		return {'is_github': False}


def _compose_candidates(base_dir: str) -> List[str]:
	cands = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']
	out: List[str] = []
	try:
		if not os.path.isdir(base_dir):
			return out
		for nm in cands:
			p = os.path.join(base_dir, nm)
			if os.path.exists(p):
				out.append(p)
	except Exception:
		pass
	return out


def _normalize_vuln_record_path(rec: Dict[str, str], repo_root: Optional[str] = None) -> None:
	"""Best-effort normalize a vulnerability record Path for the local runtime host.

	- Remaps absolute paths that reference outputs/installed_vuln_catalogs to the local repo root.
	- Resolves relative paths against repo_root.
	- Leaves URLs untouched.
	"""
	try:
		if not isinstance(rec, dict):
			return
		raw = rec.get('Path') or rec.get('path')
		if not raw:
			return
		p = str(raw).strip()
		if not p:
			return
		try:
			if re.match(r'^https?://', p, re.IGNORECASE):
				return
		except Exception:
			pass
		if repo_root is None:
			try:
				repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
			except Exception:
				repo_root = None
		if repo_root:
			# Remap installed catalog absolute paths from a different host.
			try:
				norm = p.replace('\\', '/')
				marker = '/outputs/installed_vuln_catalogs/'
				if marker in norm:
					suffix = norm.split(marker, 1)[1]
					candidate = os.path.join(repo_root, 'outputs', 'installed_vuln_catalogs', suffix)
					rec['Path'] = os.path.abspath(candidate)
					return
			except Exception:
				pass
			# Resolve relative path to repo root.
			try:
				if not os.path.isabs(p):
					rec['Path'] = os.path.abspath(os.path.join(repo_root, p))
					return
			except Exception:
				pass
		return
	except Exception:
		return


def _compose_path_from_download(rec: Dict[str, str], out_base: str = "/tmp/vulns", compose_name: str = 'docker-compose.yml') -> Optional[str]:
	"""Resolve local compose path for a previously downloaded catalog item (webapp stores under /tmp/vulns).

	Returns a file path if found, else None.
	"""
	try:
		name = (rec.get('Name') or '').strip()
		path = (rec.get('Path') or '').strip()
		safe = _safe_name(name or 'vuln')
		vdir = os.path.join(out_base, safe)
		gh = _parse_github_url(path)
		if gh.get('is_github'):
			repo_dir = os.path.join(vdir, '_repo')
			sub = gh.get('subpath') or ''
			is_file_sub = bool(sub) and sub.lower().endswith(('.yml', '.yaml'))
			if is_file_sub:
				p = os.path.join(repo_dir, sub)
				return p if os.path.exists(p) else None
			base = os.path.join(repo_dir, sub) if sub else repo_dir
			pref = os.path.join(base, compose_name)
			if os.path.exists(pref):
				return pref
			cand = _compose_candidates(base)
			return cand[0] if cand else None
		else:
			p = os.path.join(vdir, compose_name)
			return p if os.path.exists(p) else None
	except Exception:
		return None


def _images_pulled_for_compose(yml_path: str) -> bool:
	try:
		import subprocess
		import shutil as _sh
		if not _sh.which('docker'):
			return False
		proc = subprocess.run(['docker', 'compose', '-f', yml_path, 'config', '--images'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
		if proc.returncode != 0:
			return False
		images = [ln.strip() for ln in (proc.stdout or '').splitlines() if ln.strip()]
		if not images:
			return False
		for img in images:
			p2 = subprocess.run(['docker', 'image', 'inspect', img], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
			if p2.returncode != 0:
				return False
		return True
	except Exception:
		return False


def extract_compose_images_and_container_names(yml_path: str) -> tuple[list[str], list[str]]:
	"""Best-effort parse of docker-compose YAML to extract image and container_name values.

	This intentionally does not require Docker to be installed; it only parses the YAML.
	"""
	images: list[str] = []
	containers: list[str] = []
	try:
		if not yml_path or (not os.path.exists(yml_path)):
			return images, containers
		try:
			import yaml  # type: ignore
		except Exception:
			return images, containers
		with open(yml_path, 'r', encoding='utf-8', errors='ignore') as f:
			doc = yaml.safe_load(f)  # type: ignore
		if not isinstance(doc, dict):
			return images, containers
		svcs = doc.get('services')
		if not isinstance(svcs, dict):
			return images, containers
		for _svc_name, svc in svcs.items():
			if not isinstance(svc, dict):
				continue
			img = svc.get('image')
			if isinstance(img, str) and img.strip():
				images.append(img.strip())
			cn = svc.get('container_name')
			if isinstance(cn, str) and cn.strip():
				containers.append(cn.strip())
		# De-dupe while keeping order
		images = list(dict.fromkeys(images))
		containers = list(dict.fromkeys(containers))
		return images, containers
	except Exception:
		return [], []


def detect_docker_conflicts_for_compose_files(paths: list[str]) -> dict:
	"""Check for Docker container/image name conflicts for the given compose file paths.

	Returns a dict with keys: containers (list[str]), images (list[str]).
	"""
	conflicting_containers: list[str] = []
	conflicting_images: list[str] = []
	try:
		import subprocess
		import shutil as _sh
		if not paths:
			return {'containers': [], 'images': []}
		if not _sh.which('docker'):
			return {'containers': [], 'images': []}
		all_images: list[str] = []
		all_container_names: list[str] = []
		for p in paths:
			imgs, cns = extract_compose_images_and_container_names(p)
			all_images.extend(imgs)
			all_container_names.extend(cns)
		all_images = list(dict.fromkeys([s for s in all_images if s]))
		all_container_names = list(dict.fromkeys([s for s in all_container_names if s]))

		for cn in all_container_names:
			try:
				p2 = subprocess.run(['docker', 'container', 'inspect', cn], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
				if p2.returncode == 0:
					conflicting_containers.append(cn)
			except Exception:
				continue

		for img in all_images:
			try:
				p3 = subprocess.run(['docker', 'image', 'inspect', img], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
				if p3.returncode == 0:
					conflicting_images.append(img)
			except Exception:
				continue
		return {
			'containers': list(dict.fromkeys(conflicting_containers)),
			'images': list(dict.fromkeys(conflicting_images)),
		}
	except Exception:
		return {'containers': [], 'images': []}


def remove_docker_conflicts(conflicts: dict) -> dict:
	"""Best-effort removal of conflicting Docker containers/images.

	Returns a dict with removal results.
	"""
	result = {
		'removed_containers': [],
		'removed_images': [],
		'container_errors': {},
		'image_errors': {},
	}
	try:
		import subprocess
		import shutil as _sh
		if not _sh.which('docker'):
			return result
		containers = conflicts.get('containers') if isinstance(conflicts, dict) else []
		images = conflicts.get('images') if isinstance(conflicts, dict) else []
		if not isinstance(containers, list):
			containers = []
		if not isinstance(images, list):
			images = []
		for cn in containers:
			try:
				p = subprocess.run(['docker', 'rm', '-f', str(cn)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
				if p.returncode == 0:
					result['removed_containers'].append(str(cn))
				else:
					out = (p.stdout or '').strip()[-500:]
					result['container_errors'][str(cn)] = out or f'rc={p.returncode}'
			except Exception as exc:
				result['container_errors'][str(cn)] = str(exc)
		for img in images:
			try:
				p = subprocess.run(['docker', 'image', 'rm', '-f', str(img)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
				if p.returncode == 0:
					result['removed_images'].append(str(img))
				else:
					out = (p.stdout or '').strip()[-500:]
					result['image_errors'][str(img)] = out or f'rc={p.returncode}'
			except Exception as exc:
				result['image_errors'][str(img)] = str(exc)
		return result
	except Exception:
		return result


def _eligible_compose_items(catalog: Iterable[Dict[str, str]], v_type: Optional[str], v_vector: Optional[str], out_base: str = "/tmp/vulns") -> List[Dict[str, str]]:
	"""Filter catalog to docker-compose items matching type/vector and with local compose pulled.
	v_type/v_vector may be 'Random' or falsy to indicate no filtering on that dimension.
	"""
	vt = (v_type or '').strip().lower()
	vv = (v_vector or '').strip().lower()
	items: List[Dict[str, str]] = []
	for it in catalog:
		t = (it.get('Type') or '').strip().lower()
		if t != 'docker-compose':
			continue
		if vt and vt != 'random' and t != vt:
			# type mismatch; note vt would be 'docker-compose' normally
			continue
		vec = (it.get('Vector') or '').strip().lower()
		if vv and vv != 'random' and vec != vv:
			continue
		yml = _compose_path_from_download(it, out_base=out_base)
		if not yml or not os.path.exists(yml):
			continue
		if not _images_pulled_for_compose(yml):
			continue
		items.append(it)
	return items


def assign_compose_to_nodes(node_names: List[str], density: float, items_cfg: List[dict], catalog: List[Dict[str, str]], out_base: str = "/tmp/vulns", require_pulled: bool = True, base_host_pool: int | None = None, seed: int | None = None, shuffle_nodes: bool = True) -> Dict[str, Dict[str, str]]:
	"""Assign docker-compose vulnerabilities to nodes.

	Rules (updated semantics):
	- Weight-based vulnerability rows (v_metric == Weight or default) allocate up to
	  round(density * base_host_pool) nodes, where base_host_pool is the scenario
	  "Count for Density". Additive Count rows (v_metric == Count or Specific with
	  explicit v_count) do NOT contribute to the density base and are applied in
	  addition to the density-derived allocation.
	- Count rows are allocated first (absolute), consuming nodes from the pool.
	- Weight rows then allocate from remaining nodes up to the density target.
	- 'Category' is treated as 'Type/Vector' for normalization.
	- If require_pulled is True, only locally pulled compose items are eligible.

	Returns: mapping of node_name -> catalog record (docker-compose entries only).
	"""
	if not node_names or not items_cfg:
		return {}

	# Determine base for density (fallback to total nodes if missing)
	try:
		base_for_density = int(base_host_pool) if (base_host_pool is not None and int(base_host_pool) >= 0) else len(node_names)
	except Exception:
		base_for_density = len(node_names)
	dens = max(0.0, min(1.0, float(density or 0.0)))
	# Use floor (not round) to align with router density semantics and avoid over-allocation
	import math as _math
	density_target = int(_math.floor(dens * base_for_density + 1e-9))

	# Logging (best-effort)
	try:
		import logging as _logging
		_logging.getLogger(__name__).debug(
			"assign_compose_to_nodes: base_for_density=%d total_nodes=%d dens=%.3f density_target=%d",
			base_for_density, len(node_names), dens, density_target
		)
	except Exception:
		pass

	rng = random.Random(seed) if seed is not None else random.Random()
	nodes_pool = list(node_names)
	if shuffle_nodes:
		rng.shuffle(nodes_pool)
	assigned: Dict[str, Dict[str, str]] = {}

	# Normalize and classify items
	norm_items: List[dict] = []
	for it in items_cfg:
		it2 = dict(it)
		if (it2.get('selected') or '') == 'Category':
			it2['selected'] = 'Type/Vector'
		norm_items.append(it2)

	# Normalize catalog record paths (important for remote CORE VM).
	try:
		for r in catalog or []:
			try:
				_normalize_vuln_record_path(r)
			except Exception:
				continue
	except Exception:
		pass

	count_items: List[dict] = []
	weight_items: List[dict] = []
	for it in norm_items:
		sel = (it.get('selected') or '').strip()
		metric = (it.get('v_metric') or '').strip()  # optional
		has_count = False
		if metric.lower() == 'count':
			has_count = True
		# Specific with v_count provided is also treated as count-based
		if sel == 'Specific':
			try:
				if int(it.get('v_count') or 0) > 0:
					has_count = True
			except Exception:
				pass
		if has_count:
			count_items.append(it)
		else:
			weight_items.append(it)

	def pop_nodes(k: int) -> List[str]:
		nonlocal nodes_pool
		k = max(0, min(k, len(nodes_pool)))
		taken = nodes_pool[:k]
		nodes_pool = nodes_pool[k:]
		return taken

	# 1) Allocate Count items (absolute, additive)
	for it in count_items:
		try:
			req = int(it.get('v_count') or 0)
		except Exception:
			req = 0
		if req <= 0 or not nodes_pool:
			continue
		sel = (it.get('selected') or 'Type/Vector').strip()
		pool: List[Dict[str, str]] = []
		if sel == 'Specific':
			nm = (it.get('v_name') or '').strip()
			pp = (it.get('v_path') or '').strip()
			rec: Optional[Dict[str, str]] = None
			for r in catalog:
				if r.get('Name') == nm and r.get('Path') == pp and _norm_type(r.get('Type') or '') == 'docker-compose':
					rec = r
					break
			if rec is None and pp:
				# synthetic fallback
				rec = {"Name": nm or 'vuln', "Path": pp, "Type": 'docker-compose', "Vector": it.get('v_vector') or ''}
			if rec:
				pool = [rec]
		else:  # Type/Vector
			if require_pulled:
				pool = _eligible_compose_items(catalog, it.get('v_type'), it.get('v_vector'), out_base=out_base)
			else:
				vt = _norm_type(it.get('v_type') or '')
				vv = (it.get('v_vector') or '').strip().lower()
				for r in catalog:
					if _norm_type(r.get('Type') or '') != 'docker-compose':
						continue
					if vt and vt != 'random' and _norm_type(r.get('Type') or '') != vt:
						continue
					if vv and vv != 'random' and (r.get('Vector') or '').strip().lower() != vv:
						continue
					pool.append(r)
		if not pool:
			continue
		take_nodes = pop_nodes(req)
		if not take_nodes:
			break
		# choose (with replacement if needed) for each node
		for nn in take_nodes:
			rec = rng.choice(pool)
			# ensure compose is present if required (only matters for Specific synthetic)
			if require_pulled:
				pth = _compose_path_from_download(rec, out_base=out_base)
				if not pth or not _images_pulled_for_compose(pth):
					continue
			assigned[nn] = rec
			try:
				logger.info(
					"[vuln-assign] count allocation node=%s name=%s path=%s",
					nn,
					rec.get('Name'),
					rec.get('Path'),
				)
			except Exception:
				pass

	# 2) Allocate Weight items up to density_target (independent of how many count nodes consumed)
	if density_target <= 0 or not weight_items or not nodes_pool:
		return assigned
	remaining = min(density_target, len(nodes_pool))

	# Gather weights
	weights: List[Tuple[dict, float]] = []
	total_w = 0.0
	for it in weight_items:
		try:
			w = float(it.get('v_weight') or it.get('factor') or 0.0)
		except Exception:
			w = 0.0
		if w > 0:
			weights.append((it, w))
			total_w += w
	if total_w <= 0:
		# even split
		weights = [(it, 1.0) for it in weight_items]
		total_w = float(len(weight_items))

	# Compute integer allocations with remainder distribution
	allocs: List[Tuple[dict, int]] = []
	remainders: List[Tuple[float, int]] = []  # (fractional_part, index)
	for idx, (it, w) in enumerate(weights):
		exact = (w / total_w) * remaining
		base_cnt = int(exact)
		allocs.append((it, base_cnt))
		remainders.append((exact - base_cnt, idx))
	used = sum(c for _, c in allocs)
	left = remaining - used
	# sort by largest fractional remainder
	remainders.sort(key=lambda x: x[0], reverse=True)
	ri = 0
	while left > 0 and ri < len(remainders):
		_, idx = remainders[ri]
		it, c = allocs[idx]
		allocs[idx] = (it, c + 1)
		left -= 1
		ri += 1

	# Perform allocations
	for it, cnt in allocs:
		if cnt <= 0 or not nodes_pool:
			continue
		sel = (it.get('selected') or '').strip()
		pool: List[Dict[str, str]] = []
		if sel == 'Type/Vector':
			v_type = (it.get('v_type') or 'docker-compose').strip()
			v_vec = (it.get('v_vector') or 'Random').strip()
			if require_pulled:
				pool = _eligible_compose_items(catalog, v_type, v_vec, out_base=out_base)
			else:
				# lenient filter (no file/image checks)
				vt = _norm_type(v_type)
				vv = v_vec.strip().lower()
				for r in catalog:
					if _norm_type(r.get('Type') or '') != 'docker-compose':
						continue
					if vt and vt != 'random' and _norm_type(r.get('Type') or '') != vt:
						continue
					if vv and vv != 'random' and (r.get('Vector') or '').strip().lower() != vv:
						continue
					pool.append(r)
		elif sel == 'Specific':
			# Specific without count behaves like Type/Vector random
			if require_pulled:
				pool = _eligible_compose_items(catalog, 'docker-compose', 'Random', out_base=out_base)
			else:
				pool = [r for r in catalog if _norm_type(r.get('Type') or '') == 'docker-compose']
		else:
			# Default: any docker-compose
			if require_pulled:
				pool = _eligible_compose_items(catalog, 'docker-compose', 'Random', out_base=out_base)
			else:
				pool = [r for r in catalog if _norm_type(r.get('Type') or '') == 'docker-compose']
		if not pool:
			continue
		take_nodes = pop_nodes(cnt)
		if not take_nodes:
			break
		# sample with replacement if pool smaller than cnt
		for nn in take_nodes:
			rec = rng.choice(pool)
			assigned[nn] = rec
			try:
				logger.info(
					"[vuln-assign] weight allocation node=%s name=%s path=%s",
					nn,
					rec.get('Name'),
					rec.get('Path'),
				)
			except Exception:
				pass

	return assigned


def _safe_name(s: str) -> str:
	s = s.strip().lower()
	s = re.sub(r'[^a-z0-9._-]+', '-', s)
	s = s.strip('-_.')
	return s or 'vuln'


def _github_tree_to_raw(base_url: str, filename: str) -> str | None:
	"""Convert a GitHub tree/blob URL to a raw file URL if possible."""
	try:
		m = re.match(r'^https?://github.com/([^/]+)/([^/]+)/(tree|blob)/([^/]+)/(.*)$', base_url.strip())
		if not m:
			return None
		user, repo, _kind, branch, path = m.groups()
		# Use provided filename under that path
		path = path.strip('/')
		file_part = filename.strip('/')
		raw = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}/{file_part}"
		return raw
	except Exception:
		return None


def _guess_compose_raw_url(path: str, compose_name: str = 'docker-compose.yml') -> Optional[str]:
	"""Best-effort: given a catalog Path, try to produce a raw URL to a compose file.

	Supports:
	- GitHub tree URLs pointing to a directory: append compose_name via raw content endpoint
	- GitHub blob URLs pointing directly to a .yml/.yaml file
	- Direct HTTP(S) URLs ending with .yml/.yaml
	"""
	try:
		p = (path or '').strip()
		if not p:
			return None
		# direct raw file
		if p.lower().endswith(('.yml', '.yaml')):
			# If it's a github blob URL, convert to raw
			m = re.match(r'^https?://github.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$', p)
			if m:
				user, repo, branch, rest = m.groups()
				return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{rest}"
			return p
		# GitHub tree URL to a directory
		raw = _github_tree_to_raw(p, compose_name)
		if raw:
			return raw
		# Otherwise, append compose_name naively
		p2 = p.rstrip('/') + '/' + compose_name
		return p2
	except Exception:
		return None


def _download_to(path: str, dest_path: str, timeout: float = 30.0) -> bool:
	"""Download a URL or copy a local file to dest_path. Returns True on success."""
	try:
		if not path:
			return False
		if re.match(r'^https?://', path, re.IGNORECASE):
			with urllib.request.urlopen(path, timeout=timeout) as resp:
				data = resp.read(5_000_000)
			os.makedirs(os.path.dirname(dest_path), exist_ok=True)
			with open(dest_path, 'wb') as f:
				f.write(data)
			return True
		# Local file path
		if os.path.exists(path):
			os.makedirs(os.path.dirname(dest_path), exist_ok=True)
			shutil.copy2(path, dest_path)
			return True
		return False
	except Exception:
		return False


def _strip_port_mapping_value(port_value: str) -> str:
	"""Return only the container-side port component from a port mapping string."""
	text = str(port_value).strip()
	if ':' not in text:
		return text
	parts = text.split(':')
	if not parts:
		return text
	container_segment = parts[-1].strip()
	return container_segment or text


def _prune_service_ports(service: Dict[str, object]) -> None:
	"""Update a docker-compose service entry to drop published host ports."""
	if not isinstance(service, dict):
		return
	ports = service.get('ports')
	if not ports or not isinstance(ports, list):
		return
	changed = False
	new_ports: List[object] = []
	for entry in ports:
		if isinstance(entry, str):
			value = entry.strip()
			if ':' in value and not value.startswith('{'):
				new_value = _strip_port_mapping_value(value)
				if new_value != value:
					changed = True
					new_ports.append(new_value)
				continue
		elif isinstance(entry, dict):
			entry_copy = dict(entry)
			removed = False
			if 'published' in entry_copy:
				entry_copy.pop('published', None)
				removed = True
			if 'host_ip' in entry_copy:
				entry_copy.pop('host_ip', None)
				removed = True
			if removed:
				changed = True
			new_ports.append(entry_copy)
			continue
		new_ports.append(entry)
	if changed:
		service['ports'] = new_ports


def _force_service_network_mode_none(service: Dict[str, object]) -> None:
	"""Force a docker-compose service to run without Docker-managed networking.

	This prevents Docker from injecting an eth0 + default gateway (bridge/NAT),
	so CORE can own all container networking via interfaces it adds.
	"""
	if not isinstance(service, dict):
		return
	# Compose cannot combine explicit networks with network_mode.
	service.pop('networks', None)
	service['network_mode'] = 'none'


def _force_compose_no_network(compose_obj: dict) -> dict:
	"""Best-effort: make all services run with network_mode: none.

	Also drops top-level networks to avoid compose validation conflicts.
	"""
	try:
		if not isinstance(compose_obj, dict):
			return compose_obj
		services = compose_obj.get('services')
		if not isinstance(services, dict):
			return compose_obj
		for _svc_name, svc in services.items():
			if isinstance(svc, dict):
				_force_service_network_mode_none(svc)
				# With network_mode none, host port publishing is meaningless and can
				# create collisions or validation errors. Drop ports entirely.
				svc.pop('ports', None)
		compose_obj.pop('networks', None)
		return compose_obj
	except Exception:
		return compose_obj


def _compose_force_no_network_enabled() -> bool:
	"""Whether generated vuln docker-compose stacks should run with network_mode: none.

	Default: enabled (Option B). Disable by setting `CORETG_COMPOSE_FORCE_NO_NETWORK=0/false/off`.
	"""
	val = os.getenv('CORETG_COMPOSE_FORCE_NO_NETWORK')
	if val is None:
		return True
	return str(val).strip().lower() not in ('0', 'false', 'no', 'off', '')


def _compose_force_root_workdir_enabled() -> bool:
	"""Whether to force `working_dir: /` on generated vuln docker-compose services.

	Rationale: CORE services (e.g., DefaultRoute) can create/chmod relative paths inside
	Docker nodes. Docker exec defaults to the container's WORKDIR, while docker cp uses
	paths relative to the container filesystem root. For images with non-root WORKDIR,
	this can cause CORE to fail to chmod service files that were copied into `/`.

	Default: enabled. Disable by setting `CORETG_COMPOSE_FORCE_ROOT_WORKDIR=0/false/off`.
	"""
	val = os.getenv('CORETG_COMPOSE_FORCE_ROOT_WORKDIR')
	if val is None:
		return True
	return str(val).strip().lower() not in ('0', 'false', 'no', 'off', '')


def _force_service_workdir_root(service: Dict[str, object]) -> None:
	"""Force a compose service to run with working_dir: / (best-effort)."""
	if not isinstance(service, dict):
		return
	try:
		current = service.get('working_dir')
		if isinstance(current, str) and current.strip():
			return
	except Exception:
		pass
	service['working_dir'] = '/'


def _copy_build_contexts(obj: dict, src_dir: str, base_dir: str) -> dict:
	"""Copy build contexts into base_dir and rewrite to absolute paths.

	Helps compose files that use relative build contexts (e.g., build: .)
	so the generated compose can be run from a different directory.
	"""
	try:
		if not isinstance(obj, dict):
			return obj
		services = obj.get('services')
		if not isinstance(services, dict) or not services:
			return obj
		seen: Set[str] = set()
		for _svc_name, svc in services.items():
			if not isinstance(svc, dict):
				continue
			build = svc.get('build')
			ctx = None
			if isinstance(build, dict):
				ctx = build.get('context')
			elif isinstance(build, str):
				ctx = build
			if not isinstance(ctx, str) or not ctx.strip():
				continue
			ctx = ctx.strip()
			src_ctx = ctx if os.path.isabs(ctx) else os.path.join(src_dir, ctx)
			# Only copy when source exists and is a directory.
			if not os.path.isdir(src_ctx):
				continue
			rel = None
			try:
				if os.path.abspath(src_ctx).startswith(os.path.abspath(src_dir) + os.sep):
					rel = os.path.relpath(src_ctx, src_dir)
			except Exception:
				rel = None
			if not rel:
				rel = os.path.basename(src_ctx.rstrip(os.sep)) or 'build-context'
			dest_ctx = os.path.join(base_dir, rel)
			if dest_ctx not in seen:
				try:
					shutil.copytree(src_ctx, dest_ctx, dirs_exist_ok=True)
				except Exception:
					pass
				seen.add(dest_ctx)
			# Rewrite build context to absolute dest path
			try:
				if isinstance(build, dict):
					build['context'] = dest_ctx
					# Ensure Dockerfile path is relative to context if provided
					if isinstance(build.get('dockerfile'), str):
						build['dockerfile'] = str(build.get('dockerfile'))
					# Force host network to avoid missing bridge on CORE VM
					build.setdefault('network', 'host')
				else:
					svc['build'] = {'context': dest_ctx, 'network': 'host'}
			except Exception:
				pass
		return obj
	except Exception:
		return obj


def _prune_compose_published_ports(compose_obj: dict) -> dict:
	"""Best-effort: strip *published* host ports from all services.

	This preserves the compose networking definition (networks/network_mode) but
	removes fixed host port publishing to avoid collisions when many docker-compose
	stacks run on the same CORE host.

	Note: This does not remove container-side ports; it rewrites mappings like
	`"8080:80"` to `"80"` and removes `published/host_ip` from long-syntax entries.
	"""
	try:
		if not isinstance(compose_obj, dict):
			return compose_obj
		services = compose_obj.get('services')
		if not isinstance(services, dict):
			return compose_obj
		for _svc_name, svc in services.items():
			if isinstance(svc, dict):
				_prune_service_ports(svc)
		return compose_obj
	except Exception:
		return compose_obj


def _iter_bind_sources_from_service(svc: Dict[str, object]) -> List[str]:
	"""Return candidate host-side bind mount sources referenced by a compose service.

	Only returns non-absolute sources; caller should validate existence.
	"""
	results: List[str] = []
	if not isinstance(svc, dict):
		return results
	vols = svc.get('volumes')
	if isinstance(vols, list):
		for v in vols:
			if isinstance(v, str):
				# Format: source:target[:mode]
				parts = v.split(':', 2)
				if not parts:
					continue
				src = str(parts[0] or '').strip()
				if not src or os.path.isabs(src):
					continue
				results.append(src)
			elif isinstance(v, dict):
				vtype = str(v.get('type') or '').strip().lower()
				src = str(v.get('source') or '').strip()
				if vtype and vtype != 'bind':
					continue
				if not src or os.path.isabs(src):
					continue
				results.append(src)
	# env_file can be str or list
	env_file = svc.get('env_file')
	if isinstance(env_file, str):
		p = env_file.strip()
		if p and not os.path.isabs(p):
			results.append(p)
	elif isinstance(env_file, list):
		for p in env_file:
			if isinstance(p, str):
				ps = p.strip()
				if ps and not os.path.isabs(ps):
					results.append(ps)
	return results


def _copy_support_paths_and_absolutize_binds(compose_obj: dict, src_dir: str, base_dir: str) -> dict:
	"""Copy referenced relative bind sources into base_dir and rewrite to absolute paths.

	This makes per-node compose files runnable from any working directory.
	"""
	try:
		if not isinstance(compose_obj, dict):
			return compose_obj
		services = compose_obj.get('services')
		if not isinstance(services, dict):
			return compose_obj
		# Gather all referenced relative paths that actually exist alongside the source compose.
		seen: set[str] = set()
		for _svc_name, svc in services.items():
			if not isinstance(svc, dict):
				continue
			for rel in _iter_bind_sources_from_service(svc):
				candidate = os.path.normpath(os.path.join(src_dir, rel))
				# Only treat as support file/dir if it exists next to the source compose.
				if os.path.exists(candidate):
					seen.add(rel)

		# Copy support paths into base_dir, preserving relative structure.
		for rel in sorted(seen):
			src_path = os.path.normpath(os.path.join(src_dir, rel))
			dst_path = os.path.normpath(os.path.join(base_dir, rel))
			try:
				if os.path.isdir(src_path):
					shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
				else:
					os.makedirs(os.path.dirname(dst_path), exist_ok=True)
					shutil.copy2(src_path, dst_path)
			except Exception:
				# Best-effort: continue even if some optional paths fail.
				pass

		# Rewrite bind sources to absolute paths rooted in base_dir.
		for _svc_name, svc in services.items():
			if not isinstance(svc, dict):
				continue
			vols = svc.get('volumes')
			if isinstance(vols, list):
				new_vols: List[object] = []
				for v in vols:
					if isinstance(v, str):
						parts = v.split(':', 2)
						if not parts:
							new_vols.append(v)
							continue
						src = str(parts[0] or '').strip()
						if src and (not os.path.isabs(src)) and os.path.exists(os.path.join(src_dir, src)):
							abs_src = os.path.abspath(os.path.join(base_dir, src))
							parts[0] = abs_src
							new_vols.append(':'.join(parts))
						else:
							new_vols.append(v)
					elif isinstance(v, dict):
						v2 = dict(v)
						vtype = str(v2.get('type') or '').strip().lower()
						src = str(v2.get('source') or '').strip()
						if (not vtype or vtype == 'bind') and src and (not os.path.isabs(src)) and os.path.exists(os.path.join(src_dir, src)):
							v2['source'] = os.path.abspath(os.path.join(base_dir, src))
						new_vols.append(v2)
					else:
						new_vols.append(v)
				if new_vols != vols:
					svc['volumes'] = new_vols
			# env_file rewrite
			env_file = svc.get('env_file')
			if isinstance(env_file, str):
				p = env_file.strip()
				if p and (not os.path.isabs(p)) and os.path.exists(os.path.join(src_dir, p)):
					svc['env_file'] = os.path.abspath(os.path.join(base_dir, p))
			elif isinstance(env_file, list):
				new_env: List[object] = []
				changed = False
				for p in env_file:
					if isinstance(p, str):
						ps = p.strip()
						if ps and (not os.path.isabs(ps)) and os.path.exists(os.path.join(src_dir, ps)):
							new_env.append(os.path.abspath(os.path.join(base_dir, ps)))
							changed = True
							continue
					new_env.append(p)
				if changed:
					svc['env_file'] = new_env
		return compose_obj
	except Exception:
		return compose_obj


def _rewrite_abs_paths_from_dir_to_dir(compose_obj: dict, from_dir: str, to_dir: str) -> dict:
	"""Rewrite absolute bind/env_file sources from from_dir to to_dir.

	Also copies referenced files/dirs from from_dir into to_dir (preserving relative structure).
	"""
	try:
		if not isinstance(compose_obj, dict):
			return compose_obj
		if not from_dir or not to_dir:
			return compose_obj
		from_dir_abs = os.path.abspath(from_dir)
		to_dir_abs = os.path.abspath(to_dir)
		services = compose_obj.get('services')
		if not isinstance(services, dict):
			return compose_obj

		def _map_path(p: str) -> str:
			p_abs = os.path.abspath(p)
			if not (p_abs == from_dir_abs or p_abs.startswith(from_dir_abs + os.sep)):
				return p
			rel = os.path.relpath(p_abs, from_dir_abs)
			dst = os.path.normpath(os.path.join(to_dir_abs, rel))
			try:
				os.makedirs(os.path.dirname(dst), exist_ok=True)
				if os.path.isdir(p_abs):
					shutil.copytree(p_abs, dst, dirs_exist_ok=True)
				elif os.path.exists(p_abs):
					shutil.copy2(p_abs, dst)
			except Exception:
				pass
			return dst

		for _svc_name, svc in services.items():
			if not isinstance(svc, dict):
				continue
			vols = svc.get('volumes')
			if isinstance(vols, list):
				new_vols: List[object] = []
				changed = False
				for v in vols:
					if isinstance(v, str):
						parts = v.split(':', 2)
						if not parts:
							new_vols.append(v)
							continue
						src = str(parts[0] or '').strip()
						if src and os.path.isabs(src):
							mapped = _map_path(src)
							if mapped != src:
								parts[0] = mapped
								changed = True
						new_vols.append(':'.join(parts))
					elif isinstance(v, dict):
						v2 = dict(v)
						vtype = str(v2.get('type') or '').strip().lower()
						src = str(v2.get('source') or '').strip()
						if (not vtype or vtype == 'bind') and src and os.path.isabs(src):
							mapped = _map_path(src)
							if mapped != src:
								v2['source'] = mapped
								changed = True
						new_vols.append(v2)
					else:
						new_vols.append(v)
				if changed:
					svc['volumes'] = new_vols
			# env_file rewrite (absolute paths under from_dir)
			env_file = svc.get('env_file')
			if isinstance(env_file, str):
				p = env_file.strip()
				if p and os.path.isabs(p):
					mapped = _map_path(p)
					if mapped != p:
						svc['env_file'] = mapped
			elif isinstance(env_file, list):
				new_env: List[object] = []
				changed = False
				for p in env_file:
					if isinstance(p, str):
						ps = p.strip()
						if ps and os.path.isabs(ps):
							mapped = _map_path(ps)
							if mapped != ps:
								new_env.append(mapped)
								changed = True
								continue
					new_env.append(p)
				if changed:
					svc['env_file'] = new_env
		return compose_obj
	except Exception:
		return compose_obj


def _inject_network_mode_none_text(text: str) -> str:
	"""Fallback text-level injection of network_mode: none.

	Only used when YAML parsing isn't available; conservative best-effort.
	"""
	if 'network_mode:' in text:
		return text
	lines = text.splitlines()
	result: List[str] = []
	in_services = False
	services_indent: Optional[int] = None
	for line in lines:
		stripped = line.lstrip()
		indent = len(line) - len(stripped)
		# Enter services block
		if not in_services and stripped.startswith('services:'):
			in_services = True
			services_indent = indent
			result.append(line)
			continue
		# Exit services block when indentation drops back
		if in_services and stripped and services_indent is not None and indent <= services_indent and not stripped.startswith('#'):
			in_services = False
			services_indent = None
		# When inside services, detect service header lines like "  app:" and inject
		if in_services and services_indent is not None:
			# Service header is typically indented 2 spaces beyond services:
			if stripped.endswith(':') and not stripped.startswith(('-', '#')) and indent == services_indent + 2 and ' ' not in stripped[:-1]:
				result.append(line)
				result.append(' ' * (indent + 2) + 'network_mode: none')
				continue
		result.append(line)
	if text.endswith('\n'):
		return '\n'.join(result) + '\n'
	return '\n'.join(result)


def _inject_working_dir_root_text(text: str) -> str:
	"""Fallback text-level injection of `working_dir: /` under each service.

	Only used when YAML parsing isn't available; conservative best-effort.
	"""
	if 'working_dir:' in text:
		return text
	lines = text.splitlines()
	result: List[str] = []
	in_services = False
	services_indent: Optional[int] = None
	for line in lines:
		stripped = line.lstrip()
		indent = len(line) - len(stripped)
		if not in_services and stripped.startswith('services:'):
			in_services = True
			services_indent = indent
			result.append(line)
			continue
		if in_services and stripped and services_indent is not None and indent <= services_indent and not stripped.startswith('#'):
			in_services = False
			services_indent = None
		if in_services and services_indent is not None:
			if stripped.endswith(':') and not stripped.startswith(('-', '#')) and indent == services_indent + 2 and ' ' not in stripped[:-1]:
				result.append(line)
				result.append(' ' * (indent + 2) + 'working_dir: /')
				continue
		result.append(line)
	if text.endswith('\n'):
		return '\n'.join(result) + '\n'
	return '\n'.join(result)


def _strip_port_mappings_from_text(text: str) -> str:
	"""Best-effort removal of host->container port mappings in compose YAML text."""
	lines = text.splitlines()
	result: List[str] = []
	in_ports = False
	ports_indent: Optional[int] = None
	for line in lines:
		stripped = line.lstrip()
		indent = len(line) - len(stripped)
		if in_ports:
			if stripped and indent <= (ports_indent or 0) and not stripped.startswith('-'):
				in_ports = False
			if not in_ports:
				pass
			else:
				if stripped.startswith('-'):
					raw_entry = stripped[1:].strip()
					body = raw_entry
					comment = ''
					if '#' in raw_entry:
						hash_index = raw_entry.find('#')
						body = raw_entry[:hash_index].rstrip()
						comment = raw_entry[hash_index:].strip()
					if body and not body.startswith('{'):
						quote_char = ''
						closing_quote = ''
						content = body
						if len(body) >= 2 and body[0] in ("'", '"') and body[-1] == body[0]:
							quote_char = body[0]
							closing_quote = body[-1]
							content = body[1:-1]
						if ':' in content and ' ' not in content.split(':', 1)[0]:
							new_content = _strip_port_mapping_value(content)
							if quote_char:
								body = f"{quote_char}{new_content}{closing_quote}"
							else:
								body = new_content
							line = f"{' ' * indent}- {body}"
							if comment:
								line = f"{line} {comment}"
							result.append(line)
							continue
				if stripped.startswith('published:') or stripped.startswith('host_ip:'):
					continue
		if not in_ports and stripped.startswith('ports:'):
			in_ports = True
			ports_indent = indent
			result.append(line)
			continue
		result.append(line)
	if text.endswith('\n'):
		return '\n'.join(result) + '\n'
	return '\n'.join(result)


def _drop_key_block_from_text(text: str, key: str) -> str:
	"""Best-effort removal of a YAML mapping key block from compose YAML text.

	This is only used in the fallback (text) path when YAML parsing failed.
	It removes blocks like:
	  ports:\n    - ...
	  networks:\n    default: ...
	at any indentation level.
	"""
	try:
		key = str(key or '').strip()
		if not key:
			return text
		lines = text.splitlines()
		result: List[str] = []
		in_block = False
		block_indent: Optional[int] = None
		for line in lines:
			stripped = line.lstrip()
			indent = len(line) - len(stripped)
			if in_block:
				# End block when indentation returns to parent level (or lower)
				# and the line is not a list continuation.
				if stripped and (block_indent is not None) and indent <= block_indent and not stripped.startswith('-'):
					in_block = False
					block_indent = None
				else:
					# Skip lines within the removed block
					continue
			# Start block
			if not in_block and stripped.startswith(f'{key}:'):
				in_block = True
				block_indent = indent
				continue
			result.append(line)
		if text.endswith('\n'):
			return '\n'.join(result) + '\n'
		return '\n'.join(result)
	except Exception:
		return text


def _remove_container_names_all_services(compose_obj: dict) -> dict:
	"""Remove any container_name fields from all services to avoid collisions.

	Returns the mutated object. If services are missing, no changes are made.
	"""
	try:
		if not isinstance(compose_obj, dict):
			return compose_obj
		services = compose_obj.get('services')
		if not isinstance(services, dict) or not services:
			return compose_obj
		for svc_key, svc in list(services.items()):
			if isinstance(svc, dict) and 'container_name' in svc:
				try:
					svc.pop('container_name', None)
				except Exception:
					pass
		return compose_obj
	except Exception:
		return compose_obj


def _select_service_key(compose_obj: dict, prefer_service: Optional[str] = None) -> Optional[str]:
	"""Select a best-effort target service key from a compose object.

	Matches the selection logic used by _set_container_name_one_service.
	"""
	try:
		if not isinstance(compose_obj, dict):
			return None
		services = compose_obj.get('services')
		if not isinstance(services, dict) or not services:
			return None
		target_key: Optional[str] = None
		if prefer_service:
			pref = prefer_service.strip().lower()
			for svc_key in services.keys():
				if pref in str(svc_key).strip().lower():
					target_key = str(svc_key)
					break
		if target_key is None:
			target_key = str(next(iter(services.keys())))
		return target_key
	except Exception:
		return None


def _inject_service_bind_mount(compose_obj: dict, bind: str, prefer_service: Optional[str] = None) -> dict:
	"""Inject a bind mount into the selected service's volumes list (best-effort)."""
	try:
		if not bind or not isinstance(bind, str):
			return compose_obj
		if not isinstance(compose_obj, dict):
			return compose_obj
		services = compose_obj.get('services')
		if not isinstance(services, dict) or not services:
			return compose_obj
		svc_key = _select_service_key(compose_obj, prefer_service=prefer_service)
		if not svc_key:
			return compose_obj
		svc = services.get(svc_key)
		if not isinstance(svc, dict):
			return compose_obj
		vols = svc.get('volumes')
		# Normalize to list form.
		if vols is None:
			vol_list: List[object] = []
		elif isinstance(vols, list):
			vol_list = list(vols)
		elif isinstance(vols, str):
			vol_list = [vols]
		else:
			# Unknown structure (e.g., dict); don't mutate.
			return compose_obj
		# Avoid duplicates (string compare).
		if bind not in [str(v) for v in vol_list if v is not None]:
			vol_list.append(bind)
		svc['volumes'] = vol_list
		return compose_obj
	except Exception:
		return compose_obj


def _inject_service_environment(compose_obj: dict, env: Dict[str, str], prefer_service: Optional[str] = None) -> dict:
	"""Inject environment variables into the selected service (best-effort).

	Supports both dict-form and list-form `environment` entries.
	"""
	try:
		if not env or not isinstance(env, dict):
			return compose_obj
		if not isinstance(compose_obj, dict):
			return compose_obj
		services = compose_obj.get('services')
		if not isinstance(services, dict) or not services:
			return compose_obj
		svc_key = _select_service_key(compose_obj, prefer_service=prefer_service)
		if not svc_key:
			return compose_obj
		svc = services.get(svc_key)
		if not isinstance(svc, dict):
			return compose_obj

		cur = svc.get('environment')
		# Prefer dict form when possible.
		if cur is None:
			svc['environment'] = {k: str(v) for k, v in env.items()}
			return compose_obj
		if isinstance(cur, dict):
			new_env = dict(cur)
			for k, v in env.items():
				new_env[str(k)] = str(v)
			svc['environment'] = new_env
			return compose_obj
		if isinstance(cur, list):
			# Normalize list entries to KEY=VAL
			existing_keys = set()
			out_list: List[str] = []
			for item in cur:
				if item is None:
					continue
				text = str(item)
				out_list.append(text)
				if '=' in text:
					existing_keys.add(text.split('=', 1)[0])
			for k, v in env.items():
				ks = str(k)
				if ks in existing_keys:
					continue
				out_list.append(f"{ks}={v}")
			svc['environment'] = out_list
			return compose_obj
		# Unknown structure; don't mutate.
		return compose_obj
	except Exception:
		return compose_obj


def _inject_service_labels(compose_obj: dict, labels: Dict[str, str], prefer_service: Optional[str] = None) -> dict:
	"""Inject labels into the selected service (best-effort).

	Supports both dict-form and list-form `labels` entries.
	"""
	try:
		if not labels or not isinstance(labels, dict):
			return compose_obj
		if not isinstance(compose_obj, dict):
			return compose_obj
		services = compose_obj.get('services')
		if not isinstance(services, dict) or not services:
			return compose_obj
		svc_key = _select_service_key(compose_obj, prefer_service=prefer_service)
		if not svc_key:
			return compose_obj
		svc = services.get(svc_key)
		if not isinstance(svc, dict):
			return compose_obj

		cur = svc.get('labels')
		if cur is None:
			svc['labels'] = {str(k): str(v) for k, v in labels.items()}
			return compose_obj
		if isinstance(cur, dict):
			new_labels = dict(cur)
			for k, v in labels.items():
				new_labels[str(k)] = str(v)
			svc['labels'] = new_labels
			return compose_obj
		if isinstance(cur, list):
			existing_keys = set()
			out_list: List[str] = []
			for item in cur:
				if item is None:
					continue
				text = str(item)
				out_list.append(text)
				if '=' in text:
					existing_keys.add(text.split('=', 1)[0])
			for k, v in labels.items():
				ks = str(k)
				if ks in existing_keys:
					continue
				out_list.append(f"{ks}={v}")
			svc['labels'] = out_list
			return compose_obj
		return compose_obj
	except Exception:
		return compose_obj


def _flow_artifacts_mode() -> str:
	"""How Flow generator artifacts should be delivered into compose services.

	- copy: do not mount; emit labels so a caller can docker-cp the directory in (default)
	- mount: bind-mount ArtifactsDir into the service
	"""
	try:
		val = str(os.getenv('CORETG_FLOW_ARTIFACTS_MODE') or '').strip().lower()
		if val in ('mount', 'bind', 'bind-mount'):
			return 'mount'
		return 'copy'
	except Exception:
		return 'copy'


def _inject_files_copy_mode() -> str:
	"""How inject_files should be delivered into compose services.

	- copy: copy into a volume-mounted destination (default)
	- mount: bind-mount the source files directly into destination
	"""
	try:
		val = str(os.getenv('CORETG_INJECT_FILES_MODE') or '').strip().lower()
		if val in ('mount', 'bind', 'bind-mount'):
			return 'mount'
		return 'copy'
	except Exception:
		return 'copy'


def _norm_inject_rel(raw: str) -> str:
	s = str(raw or '').strip()
	if not s:
		return ''
	s = s.replace('\\', '/')
	while s.startswith('./'):
		s = s[2:]
	while s.startswith('/'):
		s = s[1:]
	if s.startswith('flow_artifacts/'):
		s = s[len('flow_artifacts/'):]
	if s.startswith('artifacts/'):
		s = s[len('artifacts/'):]
	while s.startswith('./'):
		s = s[2:]
	s = s.strip('/')
	if not s:
		return ''
	try:
		parts = [p for p in s.split('/') if p]
		if any(p == '..' for p in parts):
			return ''
	except Exception:
		return ''
	return s


def _split_inject_spec(raw: str) -> tuple[str, str]:
	text = str(raw or '').strip()
	if not text:
		return '', ''
	for sep in ('->', '=>'):
		if sep in text:
			left, right = text.split(sep, 1)
			return left.strip(), right.strip()
	return text, ''


def _normalize_inject_dest_dir(raw: str, *, default: str = '/tmp') -> str:
	s = str(raw or '').strip()
	if not s:
		return default
	if not s.startswith('/'):
		return default
	parts = [p for p in s.split('/') if p]
	if any(p == '..' for p in parts):
		return default
	return '/' + '/'.join(parts) if parts else default


def _expand_injects_from_outputs(out_manifest: str, inject_files: list[str]) -> list[str]:
	if not out_manifest or not os.path.exists(out_manifest):
		return list(inject_files or [])
	try:
		with open(out_manifest, 'r', encoding='utf-8') as f:
			doc = json.load(f) or {}
	except Exception:
		return list(inject_files or [])
	outputs = doc.get('outputs') if isinstance(doc, dict) else None
	if not isinstance(outputs, dict):
		return list(inject_files or [])

	def _looks_like_path(s: str) -> bool:
		return '/' in (s or '')

	out: list[str] = []
	for raw in inject_files or []:
		src_raw, dest_raw = _split_inject_spec(str(raw))
		key = str(src_raw or '').strip()
		if not key:
			continue
		if key in outputs:
			v = outputs.get(key)
			if isinstance(v, str):
				vv = v.strip()
				if vv and _looks_like_path(vv):
					out.append(f"{vv} -> {dest_raw}" if dest_raw else vv)
					continue
			if isinstance(v, list):
				vals: list[str] = []
				for item in v:
					s = str(item or '').strip()
					if s and _looks_like_path(s):
						vals.append(s)
				if vals:
					if dest_raw:
						out.extend([f"{vv} -> {dest_raw}" for vv in vals])
					else:
						out.extend(vals)
					continue
		if dest_raw:
			out.append(f"{key} -> {dest_raw}")
		else:
			out.append(key)
	return out


def _inject_copy_for_inject_files(compose_obj: dict, *, inject_files: list[str], source_dir: str, outputs_manifest: str = '', prefer_service: str = '') -> dict:
	if not isinstance(compose_obj, dict) or not inject_files:
		return compose_obj
	if source_dir:
		try:
			if not os.path.isabs(source_dir):
				source_dir = os.path.abspath(source_dir)
		except Exception:
			pass
	if not source_dir or not os.path.isdir(source_dir):
		raise RuntimeError(f"[injects] source_dir missing or not a dir: {source_dir} (inject_files={inject_files})")

	try:
		logger.info(
			"[injects] prepare injects source_dir=%s outputs_manifest=%s inject_files=%s",
			source_dir,
			outputs_manifest,
			inject_files,
		)
	except Exception:
		pass

	inject_files = _expand_injects_from_outputs(outputs_manifest, inject_files)
	try:
		logger.info("[injects] expanded injects=%s", inject_files)
	except Exception:
		pass

	services = compose_obj.get('services')
	if not isinstance(services, dict):
		return compose_obj

	# Build inject mapping: relpath -> dest_dir
	inject_map: dict[str, str] = {}
	for raw in inject_files or []:
		src_raw, dest_raw = _split_inject_spec(str(raw))
		src_raw_s = str(src_raw or '').strip()
		# If src is an absolute path, treat it as a destination path inside the
		# container and map the source to the basename in artifacts. If a dest is
		# provided, honor it but still use the basename to avoid /tmp/tmp/... paths.
		if src_raw_s.startswith('/'):
			try:
				src_raw_s = src_raw_s.rstrip('/')
			except Exception:
				pass
			parent = os.path.dirname(src_raw_s)
			base = os.path.basename(src_raw_s)
			if base:
				if dest_raw:
					dest_dir = _normalize_inject_dest_dir(dest_raw)
					inject_map[base] = dest_dir
					continue
				# No dest provided: default to /tmp to avoid /tmp/tmp/... paths.
				inject_map[base] = '/tmp'
				continue
		src_norm = _norm_inject_rel(src_raw)
		if not src_norm:
			continue
		dest_dir = _normalize_inject_dest_dir(dest_raw)
		inject_map[src_norm] = dest_dir

	if not inject_map:
		raise RuntimeError(f"[injects] no valid inject mappings produced from {inject_files}")

	# Persist inject mapping metadata for remote copy mode.
	try:
		inject_items = [{'src': k, 'dest': v} for k, v in inject_map.items()]
		obj = _inject_service_labels(
			compose_obj,
			{
				'coretg.inject.source_dir': str(source_dir),
				'coretg.inject.map': json.dumps(inject_items, ensure_ascii=False),
			},
			prefer_service=target_service,
		)
		compose_obj = obj
	except Exception:
		pass

	def _volume_name_for_dest(dest_dir: str) -> str:
		slug = dest_dir.strip('/') or 'injects'
		slug = ''.join([c if c.isalnum() else '-' for c in slug])
		while '--' in slug:
			slug = slug.replace('--', '-')
		slug = slug.strip('-') or 'injects'
		return f"inject-{slug}"[:50]

	def _select_target_service() -> str:
		if prefer_service and prefer_service in services:
			return prefer_service
			
		# fall back to first service
		for k in services.keys():
			return str(k)
		return ''

	target_service = _select_target_service()
	if not target_service or target_service not in services:
		try:
			logger.warning(
				"[injects] target service not found: %s (services=%s)",
				target_service,
				list(services.keys()),
			)
		except Exception:
			pass
		return compose_obj
	try:
		logger.info(
			"[injects] applying injects to service=%s mode=%s map=%s",
			target_service,
			_inject_files_copy_mode(),
			inject_map,
		)
	except Exception:
		pass

	mode = _inject_files_copy_mode()
	if mode == 'mount':
		# Bind-mount each source path directly into the target container.
		for rel, dest_dir in inject_map.items():
			src_path = os.path.join(source_dir, rel)
			if not os.path.exists(src_path):
				raise RuntimeError(f"[injects] missing source file for bind: {src_path}")
			bind = f"{src_path}:{dest_dir}/{rel}:ro"
			compose_obj = _inject_service_bind_mount(compose_obj, bind, prefer_service=target_service)
		return compose_obj

	# Copy mode: use a helper init service to copy into named volumes.
	copy_service_name = 'inject_copy'
	if copy_service_name in services:
		i = 2
		while f"inject_copy_{i}" in services:
			i += 1
		copy_service_name = f"inject_copy_{i}"

	copy_vols: list[Any] = []
	copy_vols.append(f"{source_dir}:/src:ro")

	dest_to_volume: dict[str, str] = {}
	dest_mounts: dict[str, str] = {}
	for dest_dir in set(inject_map.values()):
		vol_name = dest_to_volume.setdefault(dest_dir, _volume_name_for_dest(dest_dir))
		slug = vol_name.replace('inject-', '')
		mount_path = f"/dst/{slug}"
		dest_mounts[dest_dir] = mount_path
		copy_vols.append(f"{vol_name}:{mount_path}")

	missing_sources: list[str] = []
	for rel in inject_map.keys():
		src_path = os.path.join(source_dir, rel)
		if not os.path.exists(src_path):
			missing_sources.append(src_path)
	if missing_sources:
		raise RuntimeError(f"[injects] missing source files: {missing_sources}")

	cmds: list[str] = []
	for rel, dest_dir in inject_map.items():
		mount_path = dest_mounts.get(dest_dir)
		if not mount_path:
			continue
		rel_dir = os.path.dirname(rel)
		rel_dir_escaped = rel_dir.replace('"', '\\"')
		src_escaped = rel.replace('"', '\\"')
		dst_escaped = rel.replace('"', '\\"')
		if rel_dir:
			cmds.append(f"mkdir -p \"{mount_path}/{rel_dir_escaped}\"")
		cmds.append(f"cp -a \"/src/{src_escaped}\" \"{mount_path}/{dst_escaped}\"")

	if not cmds:
		raise RuntimeError("[injects] no copy commands generated; refusing to skip inject service")

	services[copy_service_name] = {
		'image': 'alpine:3.19',
		'volumes': copy_vols,
		'command': ['sh', '-lc', ' && '.join(cmds)],
	}

	# Mount volumes into target service
	for dest_dir, vol_name in dest_to_volume.items():
		bind = f"{vol_name}:{dest_dir}"
		compose_obj = _inject_service_bind_mount(compose_obj, bind, prefer_service=target_service)

	# Ensure target waits for copy service
	try:
		svc = services.get(target_service)
		if isinstance(svc, dict):
			dep = svc.get('depends_on')
			if isinstance(dep, dict):
				dep.setdefault(copy_service_name, {'condition': 'service_completed_successfully'})
				svc['depends_on'] = dep
			elif isinstance(dep, list):
				if copy_service_name not in dep:
					dep.append(copy_service_name)
				svc['depends_on'] = dep
			else:
				svc['depends_on'] = {copy_service_name: {'condition': 'service_completed_successfully'}}
	except Exception:
		pass

	# Register volumes
	try:
		top_vols = compose_obj.get('volumes')
		if not isinstance(top_vols, dict):
			top_vols = {}
		for vol_name in dest_to_volume.values():
			top_vols.setdefault(vol_name, {})
		compose_obj['volumes'] = top_vols
	except Exception:
		pass

	return compose_obj


def _ensure_list_field_has(value: object, item: str) -> List[str]:
	"""Normalize a compose field that may be a string/list and ensure item is present."""
	out: List[str] = []
	try:
		if value is None:
			out = []
		elif isinstance(value, str):
			out = [value]
		elif isinstance(value, list):
			out = [str(v) for v in value if v is not None and str(v).strip()]
		else:
			out = [str(value)]
	except Exception:
		out = []
	if item not in out:
		out.append(item)
	return out


def _write_iproute2_wrapper(out_dir: str, base_image: str) -> str:
	"""Write a minimal Dockerfile that installs baseline tooling (best-effort across distros).

	Rationale: CORE docker nodes often run with no internet access from inside the container
	(e.g., network_mode none + CORE-managed interfaces). Installing required tools at build
	time avoids runtime apt/apk/yum failures.
	"""
	os.makedirs(out_dir, exist_ok=True)
	dockerfile_path = os.path.join(out_dir, 'Dockerfile')
	lines = [
		f"FROM {base_image}",
		"",
		"RUN set -eux; \\",
		"\tif command -v apt-get >/dev/null 2>&1; then \\",
		"\t\tif ! apt-get update; then \\",
		"\t\t\trm -f /etc/apt/sources.list; \\",
		"\t\t\trm -f /etc/apt/sources.list.d/*.list || true; \\",
		"\t\t\tprintf '%s\\n' \\",
		"\t\t\t\t\"deb [trusted=yes] http://archive.debian.org/debian-security jessie/updates main\" \\",
		"\t\t\t\t\"deb [trusted=yes] http://archive.debian.org/debian jessie main\" \\",
		"\t\t\t\t\"deb [trusted=yes] http://archive.debian.org/debian stretch main\" \\",
		"\t\t\t\t\"deb [trusted=yes] http://archive.debian.org/debian stretch-updates main\" \\",
		"\t\t\t\t\"deb [trusted=yes] http://archive.debian.org/debian-security stretch/updates main\" > /etc/apt/sources.list; \\",
		"\t\t\tapt-get -o Acquire::Check-Valid-Until=false update || true; \\",
		"\t\tfi; \\",
		"\t\tapt-get install -y --no-install-recommends ca-certificates curl iproute2 ethtool iptables iputils-ping net-tools procps python3 || true; \\",
		"\t\trm -rf /var/lib/apt/lists/*; \\",
		"\telif command -v apk >/dev/null 2>&1; then \\",
		"\t\tapk add --no-cache ca-certificates curl iproute2 ethtool iptables iputils net-tools procps python3 || true; \\",
		"\telif command -v dnf >/dev/null 2>&1; then \\",
		"\t\tdnf install -y iproute ethtool iptables iputils net-tools procps python3 ca-certificates curl || true; \\",
		"\t\tdnf clean all || true; \\",
		"\telif command -v yum >/dev/null 2>&1; then \\",
		"\t\tyum install -y iproute ethtool iptables iputils net-tools procps python3 ca-certificates curl || true; \\",
		"\t\tyum clean all || true; \\",
		"\telse \\",
		"\t\techo \"No supported package manager found to install baseline tools (continuing)\" >&2; \\",
		"\tfi",
	]
	content = "\n".join(lines) + "\n"
	with open(dockerfile_path, 'w', encoding='utf-8') as f:
		f.write(content)
	return dockerfile_path


def _parse_compose_ports_entry(entry: object) -> List[Tuple[str, int]]:
	"""Convert a docker-compose ports entry into one or more (protocol, port) tuples."""
	results: List[Tuple[str, int]] = []
	try:
		if isinstance(entry, int):
			if entry > 0:
				results.append(("tcp", int(entry)))
			return results
		if isinstance(entry, str):
			text = entry.strip()
			if not text:
				return results
			if '#' in text:
				text = text.split('#', 1)[0].strip()
			if not text:
				return results
			if text.startswith('{'):
				return results
			proto = 'tcp'
			if ':' in text:
				parts = text.split(':')
				text = parts[-1].strip()
			if '/' in text:
				value, proto_part = text.split('/', 1)
				text = value.strip()
				proto = (proto_part or 'tcp').strip().lower() or 'tcp'
			else:
				proto = 'tcp'
			port = int(text)
			if port > 0:
				results.append((proto, port))
			return results
		if isinstance(entry, dict):
			proto = str(entry.get('protocol') or entry.get('mode') or 'tcp').strip().lower() or 'tcp'
			for key in ('target', 'container_port', 'port'):
				value = entry.get(key)
				if value in (None, ''):
					continue
				text = str(value).strip()
				if '/' in text:
					text = text.split('/', 1)[0].strip()
				try:
					port = int(text)
				except Exception:
					continue
				if port > 0:
					results.append((proto, port))
					break
	except Exception:
		return []
	return results


def extract_compose_ports(rec: Dict[str, str], out_base: str = "/tmp/vulns", compose_name: str = 'docker-compose.yml') -> List[Dict[str, object]]:
	"""Best-effort extraction of container ports for a docker-compose vulnerability record."""
	if not rec:
		return []
	name_key = (rec.get('Name') or rec.get('name') or '').strip()
	path_key = (rec.get('Path') or rec.get('path') or '').strip()
	cache_key = (name_key, path_key)
	if cache_key in _COMPOSE_PORT_CACHE:
		return list(_COMPOSE_PORT_CACHE[cache_key])

	ports: List[Dict[str, object]] = []
	compose_path = rec.get('compose_path')
	if compose_path and not os.path.isabs(compose_path):
		compose_path = os.path.abspath(compose_path)
	if not compose_path or not os.path.exists(compose_path):
		safe = _safe_name(name_key or 'vuln') or 'vuln'
		base_dir = os.path.join(out_base, safe)
		os.makedirs(base_dir, exist_ok=True)
		if path_key and os.path.exists(path_key):
			compose_path = path_key
		else:
			candidates = _compose_candidates(base_dir)
			if candidates:
				compose_path = candidates[0]
			else:
				raw_url = _guess_compose_raw_url(path_key, compose_name=compose_name)
				if raw_url:
					dest = os.path.join(base_dir, compose_name)
					if _download_to(raw_url, dest):
						compose_path = dest
				elif path_key:
					dest = os.path.join(base_dir, compose_name)
					if _download_to(path_key, dest):
						compose_path = dest
	if not compose_path or not os.path.exists(compose_path):
		logger.debug("extract_compose_ports: compose file unavailable for %s (path=%s)", cache_key, compose_path)
		_COMPOSE_PORT_CACHE[cache_key] = ports
		return []

	if yaml is None:
		logger.debug("extract_compose_ports: PyYAML unavailable; skipping port extraction for %s", cache_key)
		_COMPOSE_PORT_CACHE[cache_key] = ports
		return []

	try:
		with open(compose_path, 'r', encoding='utf-8') as f:
			compose_obj = yaml.safe_load(f) or {}
	except Exception as exc:
		logger.debug("extract_compose_ports: failed to parse %s: %s", compose_path, exc)
		_COMPOSE_PORT_CACHE[cache_key] = ports
		return []

	services = compose_obj.get('services') if isinstance(compose_obj, dict) else None
	if not isinstance(services, dict):
		_COMPOSE_PORT_CACHE[cache_key] = ports
		return []
	seen: Set[Tuple[str, int]] = set()
	for svc_name, svc_body in services.items():
		if not isinstance(svc_body, dict):
			continue
		ports_field = svc_body.get('ports')
		if not ports_field:
			continue
		if not isinstance(ports_field, list):
			ports_field = [ports_field]
		for entry in ports_field:
			for proto, port in _parse_compose_ports_entry(entry):
				key = (proto, port)
				if key in seen:
					continue
				seen.add(key)
				ports.append({"protocol": proto, "port": port, "service": svc_name})

	_COMPOSE_PORT_CACHE[cache_key] = ports
	if ports and 'compose_ports' not in rec:
		try:
			rec['compose_ports'] = list(ports)
		except Exception:
			pass
	return list(ports)


def prepare_compose_for_nodes(selected: List[Dict[str, str]], node_names: List[str], out_base: str = "/tmp/vulns", compose_name: str = 'docker-compose.yml') -> List[str]:
	"""Prepare per-node docker-compose files for selected docker-compose vulnerabilities.

	Steps:
	- Identify the first selected item that appears to reference a docker-compose catalog entry
	- Download its compose file to out_base/<safe_name>/<compose_name> (best-effort)
	- For each node name, copy to out_base/docker-compose-<node>.yml and set `container_name: <node>` for all services

 	Returns a list of per-node compose file paths created.
	"""
	created: List[str] = []
	if not selected or not node_names:
		return created


def prepare_compose_for_assignments(name_to_vuln: Dict[str, Dict[str, str]], out_base: str = "/tmp/vulns", compose_name: str = 'docker-compose.yml') -> List[str]:
	"""Backward compatible helper used by CLI to build per-node compose files.

	Accepts a mapping of node name -> vulnerability record and produces
	docker-compose-<node>.yml for each record whose Type is docker-compose.
	"""
	created: List[str] = []
	if not name_to_vuln:
		return created
	os.makedirs(out_base, exist_ok=True)

	def _rec_get(rec: Dict[str, str], *keys: str) -> str:
		for k in keys:
			try:
				v = rec.get(k)
			except Exception:
				v = None
			if v is None:
				continue
			try:
				s = str(v)
			except Exception:
				continue
			if s is not None:
				return s
		return ""

	def _is_docker_compose_record(rec: Dict[str, str]) -> bool:
		try:
			# Accept multiple key spellings and normalize
			vtype = _rec_get(rec, 'Type', 'type', 'v_type', 'VType')
			return _norm_type(vtype) == 'docker-compose'
		except Exception:
			return False

	def _set_container_name_for_selected_service(compose_obj: dict, node_name: str, prefer_service: Optional[str] = None) -> dict:
		"""Set container_name for the selected service to the CORE node name (best-effort).

		NOTE: Some COREEMU deployments require container_name to match the CORE node
		name for docker-node management to work reliably.

		You can opt out by setting `CORETG_COMPOSE_SET_CONTAINER_NAME=0`.
		"""
		try:
			if not isinstance(compose_obj, dict):
				return compose_obj
			services = compose_obj.get('services')
			if not isinstance(services, dict) or not services:
				return compose_obj
			svc_key = _select_service_key(compose_obj, prefer_service=prefer_service)
			if not svc_key:
				return compose_obj
			svc = services.get(svc_key)
			if not isinstance(svc, dict):
				return compose_obj
			svc['container_name'] = str(node_name)
			return compose_obj
		except Exception:
			return compose_obj

	def _compose_set_container_name_enabled() -> bool:
		"""Whether to inject container_name into generated docker-compose files.

		Default: enabled.
		Disable by setting `CORETG_COMPOSE_SET_CONTAINER_NAME=0/false/off`.
		"""
		val = os.getenv('CORETG_COMPOSE_SET_CONTAINER_NAME')
		if val is None:
			return True
		return str(val).strip().lower() not in ('0', 'false', 'no', 'off', '')

	def _escape_mako_dollars(text: str) -> str:
		"""Escape Mako-sensitive `${...}` so they render literally in output.

		Mako treats `${var}` as an expression and will raise NameError if undefined.
		Escaping to `$${var}` renders a literal `${var}` in the final compose/bash.
		This function preserves existing `$${...}` and only escapes raw `${...}`.
		"""
		try:
			import re as _re
			# Replace occurrences of `${` not already escaped (i.e., not preceded by `$`).
			return _re.sub(r'(?<!\$)\$\{', '$${', text)
		except Exception:
			return text

	def _escape_core_printf_percents(text: str) -> str:
		"""Escape `%` so CORE's `printf "..." >> docker-compose.yml` writes literal percents.

		CORE (core-daemon) writes rendered docker-compose templates using a shell printf
		format string. Any unescaped `%` in the compose content is interpreted as a
		printf directive and can fail (e.g. `%Y` in `date +"%Y-%m-%d"`).

		We rewrite single `%` to `%%` (printf escapes) while preserving existing `%%`.
		"""
		try:
			import re as _re
			return _re.sub(r'(?<!%)%(?!%)', '%%', text)
		except Exception:
			return text

	def _escape_core_printf_backslashes(text: str) -> str:
		"""Escape backslashes so CORE's host-side printf doesn't interpret sequences like `\n`.

		CORE writes rendered docker-compose templates via a shell `printf "<content>"`.
		That means both the shell and printf can interpret backslashes, which can inject
		newlines mid-line (e.g. `\n`) and corrupt YAML indentation.

		We pre-escape each literal backslash (`\\`) to `\\\\` so that after shell double-quote
		processing and printf escape handling, the written compose contains the original
		single backslash.
		"""
		try:
			# Replace a single backslash with 4 backslashes.
			# This prevents CORE's host-side printf from interpreting sequences like `\n`
			# mid-line, which can corrupt YAML indentation.
			return text.replace('\\', '\\\\' * 2)
		except Exception:
			return text

	def _yaml_dump_literal_multiline(data: object) -> str:
		"""Dump YAML while forcing literal block style for multiline strings.

		Why: PyYAML often serializes multiline strings using `\n` escape sequences inside
		double-quoted scalars. Our CORE host-side printf escaping must escape backslashes,
		which turns `\n` into `\\n`, and that then reaches containers as a literal
		backslash-n (breaking bash conditionals like `then\\n`).

		By forcing multiline strings to use a literal block scalar (`|`), the dumped YAML
		contains real newlines instead of `\n` escape sequences, so backslash-escaping
		does not corrupt the command.
		"""
		try:
			class _CoreTGYamlDumper(yaml.SafeDumper):
				pass

			def _repr_str(dumper, value: str):
				style = '|' if '\n' in value else None
				return dumper.represent_scalar('tag:yaml.org,2002:str', value, style=style)

			_CoreTGYamlDumper.add_representer(str, _repr_str)
			return yaml.dump(data, Dumper=_CoreTGYamlDumper, sort_keys=False)
		except Exception:
			# Fall back to PyYAML default behavior.
			return yaml.safe_dump(data, sort_keys=False)
	cache: Dict[Tuple[str, str], Tuple[Optional[dict], Optional[str], Optional[str], bool]] = {}
	for node_name, rec in name_to_vuln.items():
		if not _is_docker_compose_record(rec):
			continue
		# Normalize any catalog paths embedded from another host (e.g., GUI machine).
		try:
			_normalize_vuln_record_path(rec)
		except Exception:
			pass
		try:
			logger.info(
				"[vuln] preparing docker-compose for node=%s name=%s path=%s",
				node_name,
				_rec_get(rec, 'Name', 'name', 'Title', 'title') or None,
				_rec_get(rec, 'Path', 'path') or None,
			)
		except Exception:
			pass
		key = ((_rec_get(rec, 'Name', 'name', 'Title', 'title') or '').strip(), (_rec_get(rec, 'Path', 'path') or '').strip())
		hint_text = str(rec.get('HintText') or '').strip()
		base_compose_obj: Optional[dict]
		src_path: Optional[str]
		base_dir: Optional[str]
		is_local: bool
		if key in cache:
			base_compose_obj, src_path, base_dir, is_local = cache[key]
			try:
				logger.debug(
					"[vuln] compose cache hit key=%s src=%s has_yaml=%s",
					key,
					src_path,
					base_compose_obj is not None,
				)
			except Exception:
				pass
		else:
			safe = _safe_name(key[0] or 'vuln') or 'vuln'
			base_dir = os.path.join(out_base, safe)
			os.makedirs(base_dir, exist_ok=True)
			src_path = os.path.join(base_dir, compose_name)
			ok = False
			is_local = False
			# Prefer already-downloaded compose artifacts under out_base/<safe_name>/... .
			# This avoids re-fetching from the network on offline CORE hosts.
			try:
				dl_path = _compose_path_from_download(rec, out_base=out_base, compose_name=compose_name)
				if dl_path and os.path.exists(dl_path):
					src_path = dl_path
					ok = True
			except Exception:
				pass
			if not ok:
				raw_url = _guess_compose_raw_url(key[1], compose_name=compose_name)
				if raw_url:
					logger.info("[vuln] fetching compose url=%s dest=%s", raw_url, src_path)
					ok = _download_to(raw_url, src_path)
				if not ok and key[1] and os.path.exists(key[1]):
					logger.info("[vuln] copying compose from local path=%s dest=%s", key[1], src_path)
					ok = _download_to(key[1], src_path)
					is_local = True
			if not ok:
				cache[key] = (None, None, None, False)
				try:
					logger.warning("[vuln] unable to retrieve compose for key=%s", key)
				except Exception:
					pass
				continue
			base_compose_obj = None
			if yaml is not None:
				try:
					with open(src_path, 'r', encoding='utf-8') as f:
						base_compose_obj = yaml.safe_load(f) or {}
					# Track that we successfully parsed the chosen src_path.
					# If the compose is local, copy referenced support files (e.g., ./flag.txt)
					# and rewrite relative bind sources to absolute paths under base_dir.
					try:
						if key[1] and os.path.exists(key[1]):
							src_dir = os.path.dirname(os.path.abspath(key[1]))
							base_compose_obj = _copy_support_paths_and_absolutize_binds(
								base_compose_obj,
								src_dir=src_dir,
								base_dir=base_dir,
							)
							base_compose_obj = _copy_build_contexts(
								base_compose_obj,
								src_dir=src_dir,
								base_dir=base_dir,
							)
					except Exception:
						pass
					logger.debug(
						"[vuln] parsed compose yaml key=%s services=%s",
						key,
						list((base_compose_obj.get('services') or {}).keys()),
					)
				except Exception:
					# If the cached/downloaded compose under out_base is corrupt (eg partial download
					# or non-YAML error page), fall back to parsing the original local path (key[1])
					# when available.
					logger.exception("[vuln] yaml parse error for compose path=%s", src_path)
					base_compose_obj = None
					try:
						fallback_path = key[1] if (key[1] and os.path.exists(key[1])) else None
						if fallback_path and os.path.abspath(fallback_path) != os.path.abspath(src_path):
							with open(fallback_path, 'r', encoding='utf-8') as f2:
								base_compose_obj = yaml.safe_load(f2) or {}
							# Mark this as a local template so downstream can isolate binds/hints per node.
							is_local = True
							src_path_bad = src_path
							src_path = fallback_path
							# Best-effort self-heal the cached path for future runs.
							try:
								shutil.copy2(fallback_path, src_path_bad)
							except Exception:
								pass
							try:
								src_dir = os.path.dirname(os.path.abspath(fallback_path))
								base_compose_obj = _copy_support_paths_and_absolutize_binds(
									base_compose_obj,
									src_dir=src_dir,
									base_dir=base_dir,
								)
								base_compose_obj = _copy_build_contexts(
									base_compose_obj,
									src_dir=src_dir,
									base_dir=base_dir,
								)
							except Exception:
								pass
							try:
								logger.warning(
									"[vuln] recovered compose yaml parse using local path=%s (was=%s)",
									fallback_path,
									src_path_bad,
								)
							except Exception:
								pass
					except Exception:
						# Keep best-effort behavior: callers may still copy the raw compose.
						base_compose_obj = None
			cache[key] = (base_compose_obj, src_path, base_dir, is_local)
		out_path = os.path.join(out_base, f"docker-compose-{node_name}.yml")
		# For troubleshooting: keep a copy of the source compose used for this node.
		# This makes it easy to diff what CORE receives vs the original vulnerability compose.
		orig_copy_path = os.path.join(out_base, f"docker-compose-{node_name}.orig.yml")
		wrote = False
		if base_compose_obj is not None and yaml is not None:
			prefer = key[0]
			# IMPORTANT: deep-copy to avoid mutating cached base YAML across nodes.
			# A shallow copy here can leak per-node wrapper image/build modifications
			# into subsequent nodes, which can cause Docker to attempt pulling the
			# wrapper tag from docker.io (unauthorized) or wrap the wrapper.
			obj = copy.deepcopy(base_compose_obj)
			# If this compose comes from a local template, isolate bind mounts per node
			# so we can materialize per-node hint files without cross-node collisions.
			try:
				if is_local and base_dir:
					node_dir = os.path.join(base_dir, f"node-{_safe_name(node_name)}")
					os.makedirs(node_dir, exist_ok=True)
					obj = _rewrite_abs_paths_from_dir_to_dir(obj, from_dir=base_dir, to_dir=node_dir)
					if hint_text:
						try:
							with open(os.path.join(node_dir, 'hint.txt'), 'w', encoding='utf-8') as hf:
								hf.write(hint_text.strip() + "\n")
						except Exception:
							pass
						try:
							html_dir = os.path.join(node_dir, 'html')
							if os.path.isdir(html_dir):
								with open(os.path.join(html_dir, 'hint.txt'), 'w', encoding='utf-8') as hf2:
									hf2.write(hint_text.strip() + "\n")
						except Exception:
							pass
			except Exception:
				pass
			# Best-effort: copy the original compose file for diffing.
			try:
				if src_path and os.path.exists(src_path) and (not os.path.exists(orig_copy_path)):
					shutil.copy2(src_path, orig_copy_path)
			except Exception:
				pass
			# Avoid name collisions: ensure no hard-coded container_name remains in any service.
			obj = _remove_container_names_all_services(obj)
			# Optional: set container_name for the selected service.
			# Default OFF because it can interfere with CORE's service execution on docker nodes.
			if _compose_set_container_name_enabled():
				obj = _set_container_name_for_selected_service(obj, node_name, prefer_service=prefer)
			# Record which service was selected (useful when a compose has multiple services).
			try:
				svc_key_selected = _select_service_key(obj, prefer_service=prefer)
				if svc_key_selected:
					rec['compose_service'] = str(svc_key_selected)
					logger.info("[vuln] compose selected service node=%s service=%s", node_name, svc_key_selected)
			except Exception:
				pass
			# Remove obsolete top-level 'version' key to suppress warnings.
			try:
				obj.pop('version', None)
			except Exception:
				pass
			# Preserve original compose networking as-authored, but strip published host
			# ports to avoid host-level collisions when multiple stacks run on the CORE VM.
			# Flow flag-generators: mount generated artifacts into the container.
			try:
				art_dir = str(rec.get('ArtifactsDir') or '').strip()
				mount_path = str(rec.get('ArtifactsMountPath') or '').strip() or '/flow_artifacts'
				# Fallback: discover latest flow artifacts directory when ArtifactsDir is missing
				# This handles the case when loading from saved XML where artifacts_dir wasn't persisted.
				if not art_dir:
					scenario_tag = str(rec.get('ScenarioTag') or '').strip()
					art_dir = _discover_flow_artifacts_dir(scenario_tag=scenario_tag, node_name=node_name, out_base=out_base) or ''
					if art_dir:
						logger.info('[vuln] fallback discovered artifacts for node=%s: %s', node_name, art_dir)
						rec['ArtifactsDir'] = art_dir
						if not rec.get('InjectSourceDir'):
							rec['InjectSourceDir'] = art_dir
				if art_dir:
					# Always emit labels so callers can inspect/copy artifacts even when mounting.
					obj = _inject_service_labels(
						obj,
						{
							'coretg.flow_artifacts.src': art_dir,
							'coretg.flow_artifacts.dest': mount_path,
						},
						prefer_service=prefer,
					)
					if _flow_artifacts_mode() != 'copy':
						bind = f"{art_dir}:{mount_path}:ro"
						obj = _inject_service_bind_mount(obj, bind, prefer_service=prefer)
			except Exception:
				pass

			# Inject allowlisted files into the target container (copy by default).
			try:
				inject_files = rec.get('InjectFiles') or rec.get('inject_files')
				source_dir = str(rec.get('InjectSourceDir') or rec.get('ArtifactsDir') or '').strip()
				outputs_manifest = str(rec.get('OutputsManifest') or '')
				if not outputs_manifest:
					# best-effort: look for outputs.json in run dir
					run_dir = str(rec.get('RunDir') or '').strip()
					cand = os.path.join(run_dir, 'outputs.json') if run_dir else ''
					if cand and os.path.exists(cand):
						outputs_manifest = cand
				if isinstance(inject_files, list) and inject_files and source_dir:
					obj = _inject_copy_for_inject_files(
						obj,
						inject_files=[str(x) for x in inject_files if x is not None],
						source_dir=source_dir,
						outputs_manifest=outputs_manifest,
						prefer_service=prefer,
					)
			except Exception:
				pass
			# Optional overlays for traffic/segmentation nodes (kept out of baseline template).
			try:
				def _truthy(val: object) -> bool:
					v = str(val or '').strip().lower()
					return v in ('1', 'true', 'yes', 'y', 'on')
				enable_traffic = _truthy(rec.get('EnableTrafficMount') or rec.get('traffic_mount') or rec.get('is_traffic_node'))
				enable_seg = _truthy(rec.get('EnableSegmentationMount') or rec.get('segmentation_mount') or rec.get('is_segmentation_node'))
				if enable_traffic:
					obj = _inject_service_bind_mount(obj, '/tmp/traffic:/tmp/traffic:ro', prefer_service=prefer)
					obj = _inject_service_environment(obj, {'CORETG_TRAFFIC_NODE': '1'}, prefer_service=prefer)
				if enable_seg:
					obj = _inject_service_bind_mount(obj, '/tmp/segmentation:/tmp/segmentation:ro', prefer_service=prefer)
					obj = _inject_service_environment(obj, {'CORETG_SEGMENTATION_NODE': '1'}, prefer_service=prefer)
			except Exception:
				pass
			# Generic compose overlays (intended for flag-sequencer).
			try:
				extra_binds = rec.get('ExtraBinds') or rec.get('ExtraVolumes')
				if isinstance(extra_binds, str):
					# Allow semicolon-separated list
					parts = [p.strip() for p in extra_binds.split(';') if p.strip()]
					for b in parts:
						obj = _inject_service_bind_mount(obj, b, prefer_service=prefer)
				elif isinstance(extra_binds, list):
					for b in extra_binds:
						if b is None:
							continue
						obj = _inject_service_bind_mount(obj, str(b), prefer_service=prefer)
			except Exception:
				pass
			try:
				extra_env = rec.get('ExtraEnv') or rec.get('ExtraEnvironment')
				if isinstance(extra_env, dict):
					obj = _inject_service_environment(obj, {str(k): str(v) for k, v in extra_env.items()}, prefer_service=prefer)
			except Exception:
				pass
			# Ensure the selected service uses a wrapper build that installs iproute2.
			try:
				skip_wrap_raw = str(rec.get('SkipIproute2Wrapper') or '').strip().lower()
				skip_wrapper = skip_wrap_raw in ('1', 'true', 'yes', 'y', 'on')
				if skip_wrapper:
					raise RuntimeError('skip_iproute2_wrapper')
				scenario_tag_raw = str(
					rec.get('ScenarioTag')
					or rec.get('scenario_tag')
					or os.getenv('CORETG_SCENARIO_TAG')
					or ''
				).strip()
				scenario_tag_safe = _safe_name(scenario_tag_raw) if scenario_tag_raw else 'scenario'
				svc_key = _select_service_key(obj, prefer_service=prefer)
				services = obj.get('services') if isinstance(obj, dict) else None
				if svc_key and isinstance(services, dict) and isinstance(services.get(svc_key), dict):
					svc = services.get(svc_key)
					base_image = str(svc.get('image') or '').strip()
					try:
						# Some base images (e.g., ActiveMQ) rely on relative startup paths.
						# Preserve their expected WORKDIR to avoid '/bin/activemq: not found'.
						if base_image and 'activemq' in base_image.lower():
							if not isinstance(svc.get('working_dir'), str) or not str(svc.get('working_dir')).strip():
								svc['working_dir'] = '/opt/activemq'
					except Exception:
						pass
					# If this compose already references our wrapper tag, don't wrap again.
					# Double-wrapping can make Docker try to pull the wrapper tag as a base image.
					if base_image.startswith('coretg/') and base_image.endswith(':iproute2'):
						raise RuntimeError('already_wrapped')
					if base_image:
						wrap_dir = os.path.join(out_base, f"docker-wrap-{scenario_tag_safe}-{_safe_name(node_name)}")
						_write_iproute2_wrapper(wrap_dir, base_image)
						# Rewrite service to build the wrapper; keep a tagged image for caching.
						# NOTE: some CORE VM Docker installs are missing the default "bridge" network,
						# which causes `docker compose build` to fail with "network bridge not found".
						# Force host networking for the build to avoid relying on the bridge network.
						svc['build'] = {'context': wrap_dir, 'dockerfile': 'Dockerfile', 'network': 'host'}
						svc['image'] = f"coretg/{scenario_tag_safe}-{_safe_name(node_name)}:iproute2"
						# Avoid pull warnings for local wrapper image.
						svc['pull_policy'] = 'never'
						# DefaultRoute needs iproute2 + NET_ADMIN in many images.
						svc['cap_add'] = _ensure_list_field_has(svc.get('cap_add'), 'NET_ADMIN')
						# CORE services often manipulate files using relative paths; force root workdir.
						try:
							if _compose_force_root_workdir_enabled():
								_force_service_workdir_root(svc)
						except Exception:
							pass
					else:
						logger.warning("[vuln] compose service has no image; cannot inject iproute2 wrapper for node=%s service=%s", node_name, svc_key)
			except Exception:
				# Best-effort: wrapper injection is optional.
				pass
				# Even if wrapper injection is skipped, force root workdir when enabled.
				try:
					if _compose_force_root_workdir_enabled():
						svc_key = _select_service_key(obj, prefer_service=prefer)
						services = obj.get('services') if isinstance(obj, dict) else None
						if svc_key and isinstance(services, dict) and isinstance(services.get(svc_key), dict):
							_force_service_workdir_root(services.get(svc_key))
				except Exception:
					pass
			# Apply published-port pruning late so overlays/wrappers can't reintroduce
			# fixed host port publishing.
			try:
				if _compose_force_no_network_enabled():
					obj = _force_compose_no_network(obj)
				else:
					obj = _prune_compose_published_ports(obj)
			except Exception:
				pass
			try:
				# Dump YAML to string first, then escape sequences that CORE's host-side printf
				# would otherwise interpret.
				text = _yaml_dump_literal_multiline(obj)
				text = _escape_core_printf_backslashes(text)
				text = _escape_mako_dollars(text)
				text = _escape_core_printf_percents(text)
				with open(out_path, 'w', encoding='utf-8') as f:
					f.write(text)
				services_keys = list((obj.get('services') or {}).keys()) if isinstance(obj, dict) else []
				logger.info("[vuln] wrote compose yaml node=%s services=%s dest=%s", node_name, services_keys, out_path)
				wrote = True
			except Exception:
				logger.exception("[vuln] failed writing compose yaml for node=%s", node_name)
		elif src_path and os.path.exists(src_path):
			try:
				shutil.copy2(src_path, out_path)
			except Exception:
				logger.exception("[vuln] failed copying compose for node=%s", node_name)
			else:
				# Best-effort: copy the original compose file for diffing.
				try:
					if src_path and os.path.exists(src_path) and (not os.path.exists(orig_copy_path)):
						shutil.copy2(src_path, orig_copy_path)
				except Exception:
					pass
				try:
					with open(out_path, 'r', encoding='utf-8', errors='ignore') as f:
						txt = f.read()
					# Remove obsolete 'version' key and all container_name lines to avoid warnings/collisions
					import re as _re
					txt = _re.sub(r'^\s*version\s*:\s*[^\n]+\n?', '', txt, flags=_re.MULTILINE)
					txt = _re.sub(r'^\s*container_name\s*:\s*[^\n]+\n?', '', txt, flags=_re.MULTILINE)
					# COREEMU: best-effort ensure container_name matches CORE node name.
					try:
						val = os.getenv('CORETG_COMPOSE_SET_CONTAINER_NAME')
						enabled = True if val is None else (str(val).strip().lower() not in ('0', 'false', 'no', 'off', ''))
					except Exception:
						enabled = True
					if enabled:
						# Insert `container_name: <node>` under the first service definition.
						# This is a fallback path (YAML parsing failed), so keep it simple.
						m = _re.search(r'^(\s*services\s*:\s*\n)([ \t]+)([^\n:]+)\s*:\s*\n', txt, flags=_re.MULTILINE)
						if m:
							indent_svc = m.group(2)
							inject = f"{indent_svc}container_name: {node_name}\n"
							insert_at = m.end(0)
							txt = txt[:insert_at] + inject + txt[insert_at:]
					if _compose_force_no_network_enabled():
						# Option B: ensure no Docker-managed network (no docker eth0/default route).
						# Also drop ports/networks blocks to avoid compose validation conflicts.
						text_sanitized = _inject_network_mode_none_text(txt)
						if _compose_force_root_workdir_enabled():
							text_sanitized = _inject_working_dir_root_text(text_sanitized)
						text_sanitized = _drop_key_block_from_text(text_sanitized, 'ports')
						text_sanitized = _drop_key_block_from_text(text_sanitized, 'networks')
					else:
						# Strip published host port mappings while preserving networks.
						text_sanitized = _strip_port_mappings_from_text(txt)
						if _compose_force_root_workdir_enabled():
							text_sanitized = _inject_working_dir_root_text(text_sanitized)
					# Escape `${...}` to prevent Mako NameError during template rendering.
					text_sanitized = _escape_core_printf_backslashes(text_sanitized)
					text_sanitized = _escape_mako_dollars(text_sanitized)
					text_sanitized = _escape_core_printf_percents(text_sanitized)
					logger.debug(
						"[vuln] sanitized compose text node=%s original_len=%s new_len=%s",
						node_name,
						len(txt),
						len(text_sanitized),
					)
					with open(out_path, 'w', encoding='utf-8') as f2:
						f2.write(text_sanitized)
				except Exception:
					logger.exception("[vuln] failed sanitizing compose text for node=%s", node_name)
				wrote = True
		if wrote:
			created.append(out_path)
			try:
				rec['compose_path'] = out_path
				logger.info("[vuln] compose file ready for node=%s compose=%s", node_name, out_path)
			except Exception:
				pass
		else:
			try:
				logger.warning("[vuln] compose not generated for node=%s", node_name)
			except Exception:
				pass
	try:
		# Verification summary for Execute progress dialog.
		expected: Dict[str, str] = {}
		for node_name, rec in (name_to_vuln or {}).items():
			try:
				if not _is_docker_compose_record(rec):
					continue
			except Exception:
				continue
			expected[node_name] = os.path.join(out_base, f"docker-compose-{node_name}.yml")
		if expected:
			present = [n for n, p in expected.items() if os.path.exists(p)]
			missing = [n for n, p in expected.items() if not os.path.exists(p)]
			logger.info(
				"[vuln] compose verification: expected=%d present=%d missing=%d",
				len(expected),
				len(present),
				len(missing),
			)
			if missing:
				for n in missing:
					rec = name_to_vuln.get(n, {}) if isinstance(name_to_vuln, dict) else {}
					name_val = (rec.get('Name') or rec.get('name') or '').strip()
					path_val = (rec.get('Path') or rec.get('path') or '').strip()
					try:
						src_hint = _compose_path_from_download(rec, out_base=out_base, compose_name=compose_name)
					except Exception:
						src_hint = None
					logger.warning(
						"[vuln] compose missing node=%s name=%s path=%s expected=%s source=%s",
						n,
						name_val or '-',
						path_val or '-',
						expected.get(n),
						src_hint or 'unresolved',
					)
	except Exception:
		pass
	return created


def process_vulnerabilities(selected: List[Dict[str, str]], out_dir: str) -> List[Tuple[Dict[str, str], str, bool, str]]:
	"""Process selected vulnerabilities.

	Minimal implementation: create a directory per item and write an info.json.
	Returns list of tuples: (record, action, ok, directory)
	"""
	os.makedirs(out_dir, exist_ok=True)
	results: List[Tuple[Dict[str, str], str, bool, str]] = []
	for rec in selected:
		name = (rec.get('Name') or '').strip() or 'vuln'
		safe = _safe_name(name)
		vdir = os.path.join(out_dir, safe)
		ok = False
		action = 'write-meta'
		try:
			os.makedirs(vdir, exist_ok=True)
			meta = {
				'Name': rec.get('Name'),
				'Path': rec.get('Path'),
				'Type': rec.get('Type'),
				'Vector': rec.get('Vector'),
			}
			with open(os.path.join(vdir, 'info.json'), 'w', encoding='utf-8') as f:
				json.dump(meta, f, indent=2)
			ok = True
		except Exception:
			ok = False
		results.append((rec, action, ok, vdir))
	return results


def start_compose_files(paths: List[str]) -> int:
	"""Start docker compose stacks for the given file paths on the host.

	Returns the number of successful "up -d" operations.
	"""
	ok = 0
	if not paths:
		return ok
	try:
		import subprocess, shutil as _sh
		def _docker_cmd() -> List[str]:
			try:
				val = os.getenv('CORETG_DOCKER_USE_SUDO')
				if val is None or str(val).strip().lower() in ('0', 'false', 'no', 'off', ''):
					return ['docker']
				pw = _docker_sudo_password()
				if pw:
					return ['sudo', '-S', '-p', '', 'docker']
				return ['sudo', '-n', 'docker']
			except Exception:
				return ['docker']
		if not _sh.which('docker'):
			return 0
		docker_cmd = _docker_cmd()
		sudo_pw = _docker_sudo_password()
		for p in paths:
			try:
				if not p or not os.path.exists(p):
					continue
				use_sudo_stdin = bool(sudo_pw) and len(docker_cmd) >= 1 and docker_cmd[0] == 'sudo' and ('-S' in docker_cmd)
				proc = subprocess.run(
					docker_cmd + ['compose', '-f', p, 'up', '-d'],
					stdout=subprocess.PIPE,
					stderr=subprocess.STDOUT,
					text=True,
					input=(sudo_pw + '\n') if use_sudo_stdin else None,
				)
				if proc.returncode == 0:
					ok += 1
			except Exception:
				continue
	except Exception:
		return ok
	return ok
