from __future__ import annotations

from typing import Any


def flow_assignment_ids_by_position(flag_assignments: list[dict[str, Any]] | None) -> list[str]:
    """Return generator IDs aligned positionally with the chain.

    This intentionally does NOT key by node_id because chains may contain
    duplicate node IDs (when allow_node_duplicates is enabled).

    Each entry may provide either:
      - id
      - generator_id

    Missing/unparseable entries yield an empty string.
    """
    if not isinstance(flag_assignments, list):
        return []

    out: list[str] = []
    for entry in flag_assignments:
        if not isinstance(entry, dict):
            out.append('')
            continue
        gid = entry.get('id')
        if gid is None or str(gid).strip() == '':
            gid = entry.get('generator_id')
        out.append(str(gid or '').strip())
    return out
