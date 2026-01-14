from __future__ import annotations

from typing import Any


def flow_generator_seed(
    *,
    base_seed: Any,
    scenario_norm: str,
    node_id: str,
    gen_id: str,
    occurrence_idx: int = 0,
) -> str:
    """Build the deterministic generator seed for Flow.

    This seed intentionally includes an occurrence index so a Flow chain may repeat the same
    (node_id, gen_id) without producing an *exact* duplicate configuration.
    """
    b = str(base_seed if base_seed not in (None, "") else "0")
    scen = str(scenario_norm or "").strip()
    nid = str(node_id or "").strip()
    gid = str(gen_id or "").strip()
    try:
        occ = int(occurrence_idx or 0)
    except Exception:
        occ = 0
    return f"{b}:{scen}:{nid}:{gid}:{occ}"
