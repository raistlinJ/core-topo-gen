from __future__ import annotations
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

from urllib.parse import urlparse
from urllib.request import urlopen


def _read_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _read_csv_rows(path: str) -> List[List[str]]:
    rows: List[List[str]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            rdr = csv.reader(f)
            for r in rdr:
                rows.append(r)
    except Exception as e:
        logging.debug("Failed reading CSV %s: %s", path, e)
    return rows


def _normalize_header(header: List[str]) -> List[str]:
    # Normalize exact schema expected by webapp data source tool
    # Required: Name, Path, Type, Startup, Vector
    # Optional: CVE, Description, References
    normalized = [h.strip() for h in header]
    return normalized


def _rows_to_catalog(rows: List[List[str]]) -> List[Dict[str, str]]:
    if not rows or len(rows) < 2:
        return []
    header = _normalize_header(rows[0])
    col_idx: Dict[str, int] = {h: i for i, h in enumerate(header)}
    result: List[Dict[str, str]] = []
    for r in rows[1:]:
        try:
            def get(k: str, default: str = "") -> str:
                i = col_idx.get(k)
                return (r[i] if i is not None and i < len(r) else default).strip()

            rec = {
                "Name": get("Name"),
                "Path": get("Path"),
                "Type": get("Type").lower(),
                "Startup": get("Startup"),
                "Vector": get("Vector").lower(),
                "CVE": get("CVE", "n/a"),
                "Description": get("Description", "n/a"),
                "References": get("References", "n/a"),
            }
            if not rec["Name"] or not rec["Path"]:
                continue
            # Filter to known types/vectors when provided
            if rec["Type"] not in ("artifact", "docker", "docker-compose", "misconfig", "incompetence", "unknown"):
                # keep but normalize unexpected types to lowercase string
                rec["Type"] = rec["Type"] or "unknown"
            if rec["Vector"] not in ("local", "remote", "unknown"):
                rec["Vector"] = rec["Vector"] or "unknown"
            result.append(rec)
        except Exception:
            continue
    return result


def load_vuln_catalog(repo_root: Optional[str] = None) -> List[Dict[str, str]]:
    """Load vulnerability catalog from enabled data sources, or fallback CSV.

    Returns a list of dicts with keys: Name, Path, Type, Startup, Vector, CVE, Description, References
    """
    if repo_root is None:
        repo_root = os.getcwd()
    # Prefer data_sources/_state.json with enabled sources
    ds_dir = os.path.join(repo_root, "data_sources")
    state_path = os.path.join(ds_dir, "_state.json")
    items: List[Dict[str, str]] = []
    state = _read_json(state_path) or {}
    for s in (state.get("sources") or []):
        try:
            if not s.get("enabled"):
                continue
            p = s.get("path")
            if not p:
                continue
            if not os.path.isabs(p):
                p = os.path.abspath(p)
            if not os.path.exists(p):
                continue
            rows = _read_csv_rows(p)
            items.extend(_rows_to_catalog(rows))
        except Exception:
            continue
    # Fallback to bundled CSV
    if not items:
        fallback = os.path.join(repo_root, "raw_datasources", "vuln_list_w_url.csv")
        if os.path.exists(fallback):
            items = _rows_to_catalog(_read_csv_rows(fallback))
    return items


def _choose_random(seq: List[dict]) -> Optional[dict]:
    try:
        import random
        if not seq:
            return None
        return random.choice(seq)
    except Exception:
        return seq[0] if seq else None


def select_vulnerabilities(vuln_density: float, vuln_items: List[dict], catalog: List[dict]) -> List[dict]:
    """Select concrete vulnerabilities based on Vulnerabilities config.

    Strategy:
    - For 'Specific': match by Name (and Path if provided).
    - For 'Type/Vector': filter catalog by Type and Vector (when not 'Random'), choose one at random.
    - For 'Random': choose one at random from the catalog.
    Returns a list of catalog entries (dicts) selected. Duplicates are removed preserving order.
    """
    out: List[dict] = []
    seen = set()
    for it in (vuln_items or []):
        sel = (it.get("selected") or "Random").strip()
        rec: Optional[dict] = None
        if sel == "Specific":
            nm = (it.get("v_name") or "").strip()
            vp = (it.get("v_path") or "").strip()
            if nm:
                for c in catalog:
                    if c.get("Name") == nm and (not vp or c.get("Path") == vp):
                        rec = c
                        break
        elif sel == "Type/Vector":
            vt = (it.get("v_type") or "Random").strip().lower()
            vv = (it.get("v_vector") or "Random").strip().lower()
            pool = [c for c in catalog if (vt == "random" or c.get("Type", "").lower() == vt) and (vv == "random" or c.get("Vector", "").lower() == vv)]
            rec = _choose_random(pool)
        else:  # Random or unknown
            rec = _choose_random(catalog)
        if rec:
            key = (rec.get("Name"), rec.get("Path"))
            if key not in seen:
                seen.add(key)
                out.append(rec)
    return out


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _github_tree_to_raw(base_url: str, filename: str) -> Optional[str]:
    """Convert a GitHub tree URL to a raw file URL if possible.

    Example:
    https://github.com/vulhub/vulhub/tree/master/appweb/CVE-2018-8715 ->
    https://raw.githubusercontent.com/vulhub/vulhub/master/appweb/CVE-2018-8715/Dockerfile
    """
    try:
        u = urlparse(base_url)
        if u.netloc.lower() != "github.com":
            return None
        parts = u.path.strip("/").split("/")
        # Expected: owner/repo/tree/branch/rest...
        if len(parts) < 4 or parts[2] != "tree":
            return None
        owner, repo, _tree, branch = parts[:4]
        rest = "/".join(parts[4:])
        raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rest}/{filename}"
        return raw
    except Exception:
        return None


def _download_text(url: str, timeout: float = 20.0) -> Optional[bytes]:
    try:
        with urlopen(url, timeout=timeout) as resp:
            # Basic content size cap: 1MB
            data = resp.read(1_000_000)
            return data
    except Exception as e:
        logging.debug("Download failed for %s: %s", url, e)
        return None


def _safe_name(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9_.-]+", "-", s)
    return s[:80] or "vuln"


def _has_command(cmd: List[str]) -> bool:
    try:
        exe = shutil.which(cmd[0])
        return exe is not None
    except Exception:
        return False


def process_vulnerabilities(selected: List[dict], out_dir: str = "/tmp/vulns") -> List[Tuple[dict, str, bool, str]]:
    """For each selected vulnerability, if Type is docker or docker-compose,
    download the relevant container file and execute docker build or docker compose pull.

    Returns a list of tuples: (vuln_rec, action_desc, success, artifact_dir)
    """
    _ensure_dir(out_dir)
    results: List[Tuple[dict, str, bool, str]] = []
    docker_ok = _has_command(["docker", "version"])
    if not docker_ok:
        logging.warning("Docker not found in PATH; skipping container actions")
    for rec in selected:
        vtype = (rec.get("Type") or "").lower()
        name = rec.get("Name") or "unknown"
        base_path = rec.get("Path") or ""
        safe = _safe_name(f"{name}")
        base_dir = os.path.join(out_dir, safe)
        _ensure_dir(base_dir)
        if vtype == "docker-compose":
            target_name = "docker-compose.yml"
            raw = _github_tree_to_raw(base_path, target_name) or (base_path.rstrip("/") + "/" + target_name)
            action = f"docker compose pull ({name})"
            ok = False
            if docker_ok:
                data = _download_text(raw)
                if data:
                    try:
                        yml_path = os.path.join(base_dir, target_name)
                        with open(yml_path, "wb") as f:
                            f.write(data)
                        # docker compose -f <file> pull
                        cmd = ["docker", "compose", "-f", yml_path, "pull"]
                        logging.info("Running: %s", " ".join(cmd))
                        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        if proc.returncode == 0:
                            ok = True
                        else:
                            logging.warning("docker compose pull failed for %s: %s", name, proc.stdout[-1000:])
                    except Exception as e:
                        logging.warning("Error running docker compose for %s: %s", name, e)
                else:
                    logging.warning("Failed to download docker-compose.yml for %s from %s", name, raw)
            results.append((rec, action, ok, base_dir))
        else:
            # Skip plain docker and any non-compose types per new requirement
            results.append((rec, "skip (non-container)", True, base_dir))
    return results
