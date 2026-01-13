from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class DagEdge:
    src: str
    dst: str
    artifact: str


@dataclass(frozen=True)
class DagBuildResult:
    order: Tuple[str, ...]
    edges: Tuple[DagEdge, ...]


def _challenge_id(ch: Dict[str, Any]) -> str:
    return str(ch.get("challenge_id") or "").strip()


def _challenge_requires(ch: Dict[str, Any]) -> List[Dict[str, Any]]:
    req = ch.get("requires")
    if isinstance(req, list):
        return [x for x in req if isinstance(x, dict)]
    return []


def _required_artifacts_from_instance(ch: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    for r in _challenge_requires(ch):
        a = str(r.get("artifact") or "").strip()
        if a:
            out.add(a)
    return out


def _requires_sources(ch: Dict[str, Any]) -> Dict[str, str]:
    """artifact -> source challenge_id (only where explicit source is provided)."""
    out: Dict[str, str] = {}
    for r in _challenge_requires(ch):
        a = str(r.get("artifact") or "").strip()
        s = str(r.get("source") or "").strip()
        if a and s:
            out[a] = s
    return out


def _plugin_id_for_challenge(ch: Dict[str, Any]) -> str:
    # New schema uses `plugin`; legacy chains use `generator.plugin`.
    p = str(ch.get("plugin") or "").strip()
    if p:
        return p
    gen = ch.get("generator")
    if isinstance(gen, dict):
        return str(gen.get("plugin") or "").strip()
    return ""


def _plugin_requires(plugin: Dict[str, Any]) -> Set[str]:
    req = plugin.get("requires")
    if not isinstance(req, list):
        return set()
    required = {str(x).strip() for x in req if str(x).strip()}
    optional = _plugin_optional_requires(plugin)
    return {x for x in required if x not in optional}


def _plugin_optional_requires(plugin: Dict[str, Any]) -> Set[str]:
    req = plugin.get("optional_requires")
    if not isinstance(req, list):
        return set()
    return {str(x).strip() for x in req if str(x).strip()}


def _plugin_produces(plugin: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    prod = plugin.get("produces")
    if not isinstance(prod, list):
        return out
    for item in prod:
        if not isinstance(item, dict):
            continue
        a = str(item.get("artifact") or "").strip()
        if a:
            out.add(a)
    return out


def build_dag(
    challenges: Sequence[Dict[str, Any]],
    *,
    plugins_by_id: Dict[str, Dict[str, Any]],
    initial_artifacts: Optional[Sequence[str]] = None,
) -> Tuple[Optional[DagBuildResult], List[str]]:
    """Build a directed graph where edges represent artifact flow, and return topo order.

    This follows the high-level approach in sequencer-examples/generators/dag_chaining_algorithm.md.

    Rules implemented:
    - Each challenge's required artifacts = instance.requires[*].artifact ∪ plugin.requires
    - Each challenge's produced artifacts = plugin.produces
    - If instance.requires[*].source is set, only that producer can satisfy the dependency.
    - We connect all compatible producers (no random binding yet).
    - We fail if a required artifact cannot be produced by any prior node (given topo order).
    """
    errors: List[str] = []

    # Index plugins and compute per-challenge requires/produces.
    ch_by_id: Dict[str, Dict[str, Any]] = {}
    reqs: Dict[str, Set[str]] = {}
    req_sources: Dict[str, Dict[str, str]] = {}
    prods: Dict[str, Set[str]] = {}

    for idx, ch in enumerate(challenges):
        if not isinstance(ch, dict):
            errors.append(f"challenges[{idx}] must be a mapping")
            continue
        cid = _challenge_id(ch)
        if not cid:
            errors.append(f"challenges[{idx}] missing challenge_id")
            continue
        if cid in ch_by_id:
            errors.append(f"duplicate challenge_id: {cid}")
            continue
        ch_by_id[cid] = ch

        plugin_id = _plugin_id_for_challenge(ch)
        if not plugin_id:
            errors.append(f"{cid}: missing plugin (or generator.plugin)")
            continue
        plugin = plugins_by_id.get(plugin_id)
        if not isinstance(plugin, dict):
            errors.append(f"{cid}: unknown plugin '{plugin_id}'")
            continue

        r = _required_artifacts_from_instance(ch) | _plugin_requires(plugin)
        reqs[cid] = r
        req_sources[cid] = _requires_sources(ch)
        prods[cid] = _plugin_produces(plugin)

        # Validate instance requires are a subset of plugin requires OR are explicitly supplied.
        # (We allow instances to declare fewer requires than the plugin; plugin.requires still applies.)
        # Also validate that instance doesn't claim requirements the plugin doesn't list.
        inst_only = _required_artifacts_from_instance(ch)
        plugin_declared = _plugin_requires(plugin) | _plugin_optional_requires(plugin)
        unknown = sorted(list(inst_only - plugin_declared))
        if unknown:
            errors.append(f"{cid}: instance requires artifacts not declared by plugin '{plugin_id}': {unknown}")

        # Legacy chains may provide produces; ensure it matches plugin produces when present.
        legacy_produces = ch.get("produces")
        if isinstance(legacy_produces, list) and legacy_produces:
            legacy_set: Set[str] = set()
            for p in legacy_produces:
                if not isinstance(p, dict):
                    continue
                a = str(p.get("artifact") or "").strip()
                if a:
                    legacy_set.add(a)
            if legacy_set and legacy_set != prods[cid]:
                errors.append(
                    f"{cid}: legacy produces {sorted(list(legacy_set))} does not match plugin '{plugin_id}' produces {sorted(list(prods[cid]))}"
                )

    if errors:
        return None, errors

    # Index producers by artifact.
    producers_by_artifact: Dict[str, List[str]] = {}
    for cid, arts in prods.items():
        for a in arts:
            producers_by_artifact.setdefault(a, []).append(cid)

    edges: List[DagEdge] = []
    incoming: Dict[str, Set[str]] = {cid: set() for cid in ch_by_id.keys()}
    outgoing: Dict[str, Set[str]] = {cid: set() for cid in ch_by_id.keys()}

    for dst, required in reqs.items():
        sources = req_sources.get(dst) or {}
        for art in required:
            if art in set(initial_artifacts or []):
                continue
            if art in sources:
                src = sources[art]
                if src not in ch_by_id:
                    errors.append(f"{dst}: requires {art} from source {src}, but {src} is not a challenge_id")
                    continue
                if art not in prods.get(src, set()):
                    errors.append(f"{dst}: requires {art} from source {src}, but {src} does not produce it")
                    continue
                edges.append(DagEdge(src=src, dst=dst, artifact=art))
                incoming[dst].add(src)
                outgoing[src].add(dst)
                continue

            producers = producers_by_artifact.get(art) or []
            for src in producers:
                if src == dst:
                    continue
                edges.append(DagEdge(src=src, dst=dst, artifact=art))
                incoming[dst].add(src)
                outgoing[src].add(dst)

            if not producers:
                errors.append(f"{dst}: requires {art}, but no plugin produces it")

    if errors:
        return None, errors

    # Topological sort (Kahn). Detect cycles.
    ready = [cid for cid, inc in incoming.items() if not inc]
    ready.sort()

    order: List[str] = []
    incoming_mut = {k: set(v) for k, v in incoming.items()}

    while ready:
        cur = ready.pop(0)
        order.append(cur)
        for nb in sorted(outgoing.get(cur, set())):
            if cur in incoming_mut.get(nb, set()):
                incoming_mut[nb].remove(cur)
                if not incoming_mut[nb]:
                    ready.append(nb)
        ready.sort()

    if len(order) != len(ch_by_id):
        remaining = sorted([cid for cid in ch_by_id.keys() if cid not in order])
        return None, [f"cycle detected or unsatisfied dependencies among: {remaining}"]

    return DagBuildResult(order=tuple(order), edges=tuple(edges)), []
