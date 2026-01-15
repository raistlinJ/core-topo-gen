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
        name = str(item.get('name') or '').strip()
        if not name:
            continue
        rec: dict[str, Any] = {
            'name': name,
            'type': str(item.get('type') or 'text').strip() or 'text',
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
            a = item.strip()
            if a:
                out.append({'artifact': a})
            continue
        if isinstance(item, dict):
            a = str(item.get('artifact') or item.get('name') or '').strip()
            if not a:
                continue
            rec: dict[str, Any] = {'artifact': a}
            if 'description' in item:
                rec['description'] = str(item.get('description') or '')
            out.append(rec)
    return out


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
    if k == 'flag-node-generator':
        base_dir = repo_root_p / 'flag_node_generators'
        flow_catalog = 'flag_node_generators'
        plugin_type = 'flag-node-generator'
    else:
        base_dir = repo_root_p / 'flag_generators'
        flow_catalog = 'flag_generators'
        plugin_type = 'flag-generator'

    if not base_dir.exists() or not base_dir.is_dir():
        return [], {}, []

    generators: list[dict[str, Any]] = []
    plugins_by_id: dict[str, dict[str, Any]] = {}
    errors: list[ManifestLoadError] = []

    for child in sorted(base_dir.iterdir()):
        if not child.is_dir():
            continue

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

        # Source: default to this directory.
        source_path = str(doc.get('source_path') or doc.get('source', {}).get('path') if isinstance(doc.get('source'), dict) else '')
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
            '_source_name': 'manifest',
            '_source_path': str(manifest_path),
            '_flow_kind': plugin_type,
            '_flow_catalog': flow_catalog,
            'description_hints': list(doc.get('description_hints') or []) if isinstance(doc.get('description_hints'), list) else [],
            'hint_templates': list(doc.get('hint_templates') or []) if isinstance(doc.get('hint_templates'), list) else [],
            'hint_template': str(doc.get('hint_template') or ''),
            'env': dict(doc.get('env') or {}) if isinstance(doc.get('env'), dict) else {},
        }

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
        gen['outputs'] = [{'name': str(x.get('artifact') or '')} for x in produces_list if str(x.get('artifact') or '').strip()]

        injects = doc.get('injects')
        inject_files: list[str] = []
        for x in _as_list(injects):
            s = str(x or '').strip()
            if s:
                inject_files.append(s)
        gen['inject_files'] = inject_files

        # Build Flow plugin contract.
        requires = []
        for x in _as_list(artifacts.get('requires')):
            s = str(x or '').strip()
            if s:
                requires.append(s)

        plugin_contract: dict[str, Any] = {
            'plugin_id': gen_id,
            'plugin_type': plugin_type,
            'version': str(doc.get('version') or '1.0'),
            'description': description,
            'requires': requires,
            'produces': produces_list,
            # Optional convenience mirror.
            'inputs': {i.get('name'): i for i in (gen.get('inputs') or []) if isinstance(i, dict) and i.get('name')},
        }

        if gen_id in plugins_by_id:
            errors.append(ManifestLoadError(path=str(manifest_path), error=f'duplicate generator id: {gen_id}'))
            continue

        plugins_by_id[gen_id] = plugin_contract
        generators.append(gen)

    generators.sort(key=lambda g: (str(g.get('name') or '').lower(), str(g.get('id') or '')))
    return generators, plugins_by_id, errors
