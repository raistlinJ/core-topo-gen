from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore


@dataclass(frozen=True)
class ManifestLoadError:
    path: str
    error: str


CANONICAL_INPUT_TYPES: set[str] = {
    'string',
    'int',
    'float',
    'number',
    'boolean',
    'json',
    'file',
    'string_list',
    'file_list',
}


LEGACY_ARTIFACT_MAP: dict[str, str] = {
    'flag': 'Flag(flag_id)',
    'filesystem.file': 'File(path)',
    'file': 'File(path)',
    'file.path': 'File(path)',
    'filepath': 'File(path)',
    'filesystem.path': 'File(path)',
}


def normalize_artifact_name(name: Any) -> str:
    raw = str(name or '').strip()
    if not raw:
        return ''
    if '(' in raw and raw.endswith(')'):
        return raw
    key = raw.strip().lower()
    return LEGACY_ARTIFACT_MAP.get(key, raw)


def normalize_manifest_input_type(type_value: Any) -> str:
    """Normalize manifest input types to a small, mandatory canonical set.

    Unknown/missing values fall back to "string".
    """
    try:
        t0 = str(type_value or '').strip().lower()
    except Exception:
        t0 = ''
    if not t0:
        return 'string'

    t = t0
    is_list = False
    try:
        if 'list' in t or t.endswith('[]'):
            is_list = True
    except Exception:
        is_list = False

    if t in CANONICAL_INPUT_TYPES:
        return t

    # File/path.
    if t in {'filepath', 'file_path', 'path', 'pathname'}:
        return 'file'
    if is_list and ('file' in t or 'path' in t):
        return 'file_list'
    if (not is_list) and ('file' in t or 'path' in t):
        return 'file'

    # Strings.
    if t in {'str', 'text'}:
        return 'string'
    if is_list and ('string' in t or 'str' in t or 'text' in t):
        return 'string_list'
    if t in {'strings'}:
        return 'string_list'
    if t in {'files'}:
        return 'file_list'
    if t.endswith('[]'):
        return 'string_list'

    # Numbers.
    if t in {'integer'}:
        return 'int'
    if t in {'double'}:
        return 'float'
    if t in {'numeric'}:
        return 'number'

    # Booleans.
    if t == 'bool':
        return 'boolean'

    # JSON-ish.
    if t in {'object', 'dict', 'map'}:
        return 'json'

    return 'string'


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _norm_kind(kind: str) -> str:
    k = str(kind or '').strip().lower().replace('_', '-').replace(' ', '-')
    if k in {'flag-generator', 'flag-generator-plugin', 'generator', 'flaggen'}:
        return 'flag-generator'
    if k in {'flag-node-generator', 'flag-node-generator-plugin', 'node-generator', 'nodegen'}:
        return 'flag-node-generator'
    return k


def _norm_inputs(inputs: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in _as_list(inputs):
        if not isinstance(item, dict):
            continue
        name = normalize_artifact_name(item.get('name'))
        if not name:
            continue
        rec: dict[str, Any] = {
            'name': name,
            'type': normalize_manifest_input_type(item.get('type')),
        }
        if 'required' in item:
            rec['required'] = bool(item.get('required'))
        if 'default' in item:
            rec['default'] = item.get('default')
        if 'sensitive' in item:
            rec['sensitive'] = bool(item.get('sensitive'))
        if 'description' in item:
            rec['description'] = str(item.get('description') or '')
        out.append(rec)
    return out


def _norm_artifact_list(value: Any) -> list[dict[str, Any]]:
    """Normalize produces list into list[{artifact, description?}]."""
    out: list[dict[str, Any]] = []
    for item in _as_list(value):
        if isinstance(item, str):
            a = normalize_artifact_name(item)
            if a:
                out.append({'artifact': a})
            continue
        if isinstance(item, dict):
            a = normalize_artifact_name(item.get('artifact') or item.get('name') or '')
            if not a:
                continue
            rec: dict[str, Any] = {'artifact': a}
            if 'description' in item:
                rec['description'] = str(item.get('description') or '')
            out.append(rec)
    return out


def _artifact_kind(artifact: str) -> str:
    """Best-effort classification for UI (file vs folder vs other).

    Artifacts are now fact-style (e.g., "File(path)"). We only need a lightweight
    hint so the UI can distinguish file vs folder.
    """
    a = str(artifact or '').strip()
    if not a:
        return ''
    try:
        from core_topo_gen.sequencer.facts import parse_fact_ref
        parsed = parse_fact_ref(a)
    except Exception:
        parsed = None
    if parsed:
        name = parsed[0].strip().lower()
        if name in {'file', 'binary', 'pcap', 'backuparchive', 'sourcecode', 'encryptedblob', 'decryptionkey'}:
            return 'file'
        if name in {'directory'}:
            return 'dir'
        return ''
    return ''


def discover_generator_manifests(
    *,
    repo_root: str | os.PathLike[str] | Path,
    kind: str,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[ManifestLoadError]]:
    """Discover and load generator manifests.

    Returns:
      - generator views (web UI shape)
      - plugin contracts by id (Flow dependency shape)
      - errors

    Manifest file name: manifest.yaml / manifest.yml

    Notes:
      - This is intentionally strict-ish: manifests missing required fields are skipped.
      - We do not attempt to read legacy v3 JSON catalogs here.
    """
    if yaml is None:
        return [], {}, [ManifestLoadError(path='', error='PyYAML not installed')]

    repo_root_p = Path(repo_root).resolve()
    k = _norm_kind(kind)

    installed_root_env = str(os.environ.get('CORETG_INSTALLED_GENERATORS_DIR') or '').strip()
    if installed_root_env:
        installed_root = Path(installed_root_env).expanduser().resolve()
    else:
        installed_root = repo_root_p / 'outputs' / 'installed_generators'

    if k == 'flag-node-generator':
        base_dirs = [repo_root_p / 'flag_node_generators', installed_root / 'flag_node_generators']
        flow_catalog = 'flag_node_generators'
        plugin_type = 'flag-node-generator'
    else:
        base_dirs = [repo_root_p / 'flag_generators', installed_root / 'flag_generators']
        flow_catalog = 'flag_generators'
        plugin_type = 'flag-generator'

    # Filter to existing directories.
    base_dirs = [p for p in base_dirs if p.exists() and p.is_dir()]
    if not base_dirs:
        return [], {}, []

    generators: list[dict[str, Any]] = []
    plugins_by_id: dict[str, dict[str, Any]] = {}
    gen_index_by_id: dict[str, int] = {}
    is_installed_by_id: dict[str, bool] = {}
    errors: list[ManifestLoadError] = []

    for base_dir in base_dirs:
        is_installed_base = False
        try:
            is_installed_base = base_dir.resolve().is_relative_to(installed_root.resolve())  # type: ignore[attr-defined]
        except Exception:
            try:
                is_installed_base = str(base_dir.resolve()).startswith(str(installed_root.resolve()))
            except Exception:
                is_installed_base = False

        for child in sorted(base_dir.iterdir()):
            if not child.is_dir():
                continue

            # Installed generator packs rewrite manifest `id` to a numeric value.
            # For UI/Flow sequencing we want stable IDs, so we remap to the
            # original `source_generator_id` when a pack marker is present.
            installed_source_id = ''
            installed_assigned_id = ''
            installed_pack_id = ''
            installed_pack_label = ''
            installed_pack_origin = ''
            if is_installed_base:
                try:
                    import json

                    marker_path = child / '.coretg_pack.json'
                    if marker_path.exists() and marker_path.is_file():
                        marker = json.loads(marker_path.read_text('utf-8', errors='ignore') or '{}')
                        if isinstance(marker, dict):
                            installed_source_id = str(marker.get('source_generator_id') or '').strip()
                            installed_assigned_id = str(marker.get('generator_id') or '').strip()
                            installed_pack_id = str(marker.get('pack_id') or '').strip()
                            installed_pack_label = str(marker.get('pack_label') or '').strip()
                            installed_pack_origin = str(marker.get('origin') or '').strip()
                except Exception:
                    installed_source_id = ''
                    installed_assigned_id = ''
                    installed_pack_id = ''
                    installed_pack_label = ''
                    installed_pack_origin = ''

            manifest_path = None
            for nm in ('manifest.yaml', 'manifest.yml'):
                p = child / nm
                if p.exists() and p.is_file():
                    manifest_path = p
                    break
            if manifest_path is None:
                continue

            try:
                doc = yaml.safe_load(manifest_path.read_text('utf-8', errors='ignore'))
            except Exception as exc:
                errors.append(ManifestLoadError(path=str(manifest_path), error=f'failed to parse yaml: {exc}'))
                continue

            if not isinstance(doc, dict):
                errors.append(ManifestLoadError(path=str(manifest_path), error='manifest must be a mapping/object'))
                continue

            try:
                mv = int(doc.get('manifest_version') or 0)
            except Exception:
                mv = 0
            if mv != 1:
                errors.append(ManifestLoadError(path=str(manifest_path), error='manifest_version must be 1'))
                continue

            gen_id = str(doc.get('id') or '').strip()
            if not gen_id:
                errors.append(ManifestLoadError(path=str(manifest_path), error='missing id'))
                continue

            # Remap installed pack numeric IDs to stable source IDs when possible.
            if is_installed_base and installed_source_id:
                gen_id = installed_source_id

            name = str(doc.get('name') or gen_id).strip() or gen_id
            description = str(doc.get('description') or '').strip()

            declared_kind = _norm_kind(doc.get('kind') or plugin_type)
            if declared_kind != plugin_type:
                # Skip mismatched manifests to avoid mixing catalogs.
                errors.append(
                    ManifestLoadError(
                        path=str(manifest_path),
                        error=f"kind mismatch: expected {plugin_type}, got {declared_kind}",
                    )
                )
                continue

            runtime = doc.get('runtime') if isinstance(doc.get('runtime'), dict) else {}
            runtime_type = str(runtime.get('type') or 'docker-compose').strip().lower()

            # Source: for installed generators, always point at the installed directory.
            # This avoids manifests overriding source_path to a repo path, which breaks deletion/runtime.
            source_path = ''
            if not is_installed_base:
                source_path = str(
                    doc.get('source_path')
                    or (doc.get('source', {}).get('path') if isinstance(doc.get('source'), dict) else '')
                )
            if not source_path:
                try:
                    source_path = str(child.relative_to(repo_root_p)).replace('\\', '/')
                except Exception:
                    source_path = str(child)

            gen: dict[str, Any] = {
                'id': gen_id,
                'name': name,
                'description': description,
                'language': str(doc.get('language') or 'python'),
                'source': {
                    'type': 'local-path',
                    'path': source_path,
                    'ref': '',
                    'subpath': '',
                    'entry': '',
                },
                # Human-facing source label used throughout the web UI.
                # Prefer the containing pack/bundle label for installed generators.
                '_source_name': (
                    installed_pack_label
                    or (f"pack:{installed_pack_id}" if installed_pack_id else '')
                    or ('repo' if (not is_installed_base) else 'installed')
                ),
                '_source_path': str(manifest_path),
                '_flow_kind': plugin_type,
                '_flow_catalog': flow_catalog,
                'description_hints': list(doc.get('description_hints') or []) if isinstance(doc.get('description_hints'), list) else [],
                'hint_templates': list(doc.get('hint_templates') or []) if isinstance(doc.get('hint_templates'), list) else [],
                'hint_template': str(doc.get('hint_template') or ''),
                'env': dict(doc.get('env') or {}) if isinstance(doc.get('env'), dict) else {},
            }

            if is_installed_base:
                if installed_assigned_id:
                    gen['_installed_assigned_id'] = installed_assigned_id
                if installed_source_id:
                    gen['_installed_source_id'] = installed_source_id
                if installed_pack_id:
                    gen['_installed_pack_id'] = installed_pack_id
                if installed_pack_label:
                    gen['_installed_pack_label'] = installed_pack_label
                if installed_pack_origin:
                    gen['_installed_pack_origin'] = installed_pack_origin

            # Runtime
            if runtime_type in {'docker-compose', 'compose'}:
                gen['compose'] = {
                    'file': str(runtime.get('compose_file') or runtime.get('file') or 'docker-compose.yml'),
                    'service': str(runtime.get('service') or 'generator'),
                }
            elif runtime_type in {'run', 'command'}:
                cmd = runtime.get('cmd')
                if isinstance(cmd, list):
                    gen['run'] = {'cmd': [str(x) for x in cmd if x is not None], 'workdir': str(runtime.get('workdir') or '${source.path}')}

            gen['inputs'] = _norm_inputs(doc.get('inputs'))

            # Provide "outputs" list for UI convenience (matches existing view shape).
            artifacts = doc.get('artifacts') if isinstance(doc.get('artifacts'), dict) else {}
            produces_list = _norm_artifact_list(artifacts.get('produces'))
            gen['outputs'] = [
                {
                    'name': str(x.get('artifact') or ''),
                    'type': _artifact_kind(str(x.get('artifact') or '')),
                }
                for x in produces_list
                if str(x.get('artifact') or '').strip()
            ]

            injects = doc.get('injects')
            inject_files: list[str] = []
            for x in _as_list(injects):
                s = normalize_artifact_name(x)
                if s:
                    inject_files.append(s)
            gen['inject_files'] = inject_files

            # Build Flow plugin contract.
            requires = []
            for x in _as_list(artifacts.get('requires')):
                s = str(x or '').strip()
                if s:
                    requires.append(s)

            optional_requires = []
            for x in _as_list(artifacts.get('optional_requires')):
                s = str(x or '').strip()
                if s:
                    optional_requires.append(s)

            plugin_contract: dict[str, Any] = {
                'plugin_id': gen_id,
                'plugin_type': plugin_type,
                'version': str(doc.get('version') or '1.0'),
                'description': description,
                'requires': requires,
                'optional_requires': optional_requires,
                'produces': produces_list,
                # Optional convenience mirror.
                'inputs': {i.get('name'): i for i in (gen.get('inputs') or []) if isinstance(i, dict) and i.get('name')},
            }

            if gen_id in plugins_by_id:
                # Prefer installed generators over repo copies when ids collide.
                # This keeps "installed-only" policies working even when a repo
                # includes template/sample generators with the same id.
                prev_installed = bool(is_installed_by_id.get(gen_id))
                if is_installed_base and (not prev_installed):
                    plugins_by_id[gen_id] = plugin_contract
                    idx = gen_index_by_id.get(gen_id)
                    if isinstance(idx, int) and 0 <= idx < len(generators):
                        generators[idx] = gen
                    else:
                        gen_index_by_id[gen_id] = len(generators)
                        generators.append(gen)
                    is_installed_by_id[gen_id] = True
                    continue

                errors.append(ManifestLoadError(path=str(manifest_path), error=f'duplicate generator id: {gen_id}'))
                continue

            plugins_by_id[gen_id] = plugin_contract
            gen_index_by_id[gen_id] = len(generators)
            is_installed_by_id[gen_id] = bool(is_installed_base)
            generators.append(gen)

    generators.sort(key=lambda g: (str(g.get('name') or '').lower(), str(g.get('id') or '')))
    return generators, plugins_by_id, errors
