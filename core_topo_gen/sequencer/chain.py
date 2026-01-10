from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


_ALLOWED_KINDS = {"flag-generator", "flag-node-generator"}


@dataclass(frozen=True)
class ChallengeArtifactRef:
    artifact: str
    source: str = ""  # optional: challenge_id


@dataclass(frozen=True)
class ChallengeProduce:
    name: str
    artifact: str


@dataclass(frozen=True)
class ChallengeSpec:
    challenge_id: str
    kind: str
    requires: Tuple[ChallengeArtifactRef, ...]
    produces: Tuple[ChallengeProduce, ...]
    plugin: str


def load_chain_yaml(path: str | Path) -> Dict[str, Any]:
    """Load a YAML chain file into a dict.

    The expected shape is a top-level mapping containing at least `challenges: [...]`.
    """
    if yaml is None:
        raise RuntimeError("PyYAML is required to load chain YAML")
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    if not isinstance(doc, dict):
        raise ValueError("Chain YAML must be a mapping at the document root")
    return doc


def validate_chain_doc(doc: Dict[str, Any]) -> Tuple[bool, List[str], Dict[str, Any]]:
    """Validate and normalize a chain document.

    Returns: (ok, errors, normalized_doc)

    Normalization:
    - Ensures `challenges` is a list.
    - Ensures each challenge has `requires` and `produces` lists (possibly empty).
    """
    errors: List[str] = []
    norm: Dict[str, Any] = dict(doc or {})

    challenges = norm.get("challenges")
    if challenges is None:
        errors.append("Missing required key: challenges")
        norm["challenges"] = []
        return False, errors, norm

    if not isinstance(challenges, list):
        errors.append("challenges must be a list")
        norm["challenges"] = []
        return False, errors, norm

    seen_ids: set[str] = set()
    for idx, ch in enumerate(challenges):
        if not isinstance(ch, dict):
            errors.append(f"challenges[{idx}] must be a mapping")
            continue

        cid = str(ch.get("challenge_id") or "").strip()
        if not cid:
            errors.append(f"challenges[{idx}] missing challenge_id")
        elif cid in seen_ids:
            errors.append(f"duplicate challenge_id: {cid}")
        else:
            seen_ids.add(cid)

        kind = str(ch.get("kind") or "").strip()
        if kind not in _ALLOWED_KINDS:
            errors.append(f"challenges[{idx}] kind must be one of {sorted(_ALLOWED_KINDS)}")

        gen = ch.get("generator")
        if not isinstance(gen, dict):
            errors.append(f"challenges[{idx}] missing generator mapping")
        else:
            plugin = str(gen.get("plugin") or "").strip()
            if not plugin:
                errors.append(f"challenges[{idx}] generator.plugin is required")

        req = ch.get("requires")
        if req is None:
            ch["requires"] = []
        elif not isinstance(req, list):
            errors.append(f"challenges[{idx}] requires must be a list")
            ch["requires"] = []

        prod = ch.get("produces")
        if prod is None:
            ch["produces"] = []
        elif not isinstance(prod, list):
            errors.append(f"challenges[{idx}] produces must be a list")
            ch["produces"] = []

        # Validate requires/provides entries.
        for r_i, r in enumerate(ch.get("requires") or []):
            if not isinstance(r, dict):
                errors.append(f"challenges[{idx}].requires[{r_i}] must be a mapping")
                continue
            art = str(r.get("artifact") or "").strip()
            if not art:
                errors.append(f"challenges[{idx}].requires[{r_i}] missing artifact")
            src = r.get("source")
            if src is not None and not isinstance(src, str):
                errors.append(f"challenges[{idx}].requires[{r_i}].source must be a string")

        for p_i, p in enumerate(ch.get("produces") or []):
            if not isinstance(p, dict):
                errors.append(f"challenges[{idx}].produces[{p_i}] must be a mapping")
                continue
            name = str(p.get("name") or "").strip()
            art = str(p.get("artifact") or "").strip()
            if not name:
                errors.append(f"challenges[{idx}].produces[{p_i}] missing name")
            if not art:
                errors.append(f"challenges[{idx}].produces[{p_i}] missing artifact")

    ok = not errors
    return ok, errors, norm


def _coerce_challenge_specs(doc: Dict[str, Any]) -> Tuple[List[ChallengeSpec], List[str]]:
    errors: List[str] = []
    challenges_raw = doc.get("challenges")
    if not isinstance(challenges_raw, list):
        return [], ["challenges must be a list"]

    out: List[ChallengeSpec] = []
    for idx, ch in enumerate(challenges_raw):
        if not isinstance(ch, dict):
            errors.append(f"challenges[{idx}] must be a mapping")
            continue

        cid = str(ch.get("challenge_id") or "").strip()
        kind = str(ch.get("kind") or "").strip()
        gen = ch.get("generator") if isinstance(ch.get("generator"), dict) else {}
        plugin = str((gen or {}).get("plugin") or "").strip()

        reqs: List[ChallengeArtifactRef] = []
        for r in (ch.get("requires") or []):
            if not isinstance(r, dict):
                continue
            art = str(r.get("artifact") or "").strip()
            if not art:
                continue
            src = str(r.get("source") or "").strip()
            reqs.append(ChallengeArtifactRef(artifact=art, source=src))

        prods: List[ChallengeProduce] = []
        for p in (ch.get("produces") or []):
            if not isinstance(p, dict):
                continue
            name = str(p.get("name") or "").strip()
            art = str(p.get("artifact") or "").strip()
            if not name or not art:
                continue
            prods.append(ChallengeProduce(name=name, artifact=art))

        if not cid:
            errors.append(f"challenges[{idx}] missing challenge_id")
        if kind not in _ALLOWED_KINDS:
            errors.append(f"challenges[{idx}] kind must be one of {sorted(_ALLOWED_KINDS)}")
        if not plugin:
            errors.append(f"challenges[{idx}] generator.plugin is required")

        out.append(
            ChallengeSpec(
                challenge_id=cid,
                kind=kind,
                requires=tuple(reqs),
                produces=tuple(prods),
                plugin=plugin,
            )
        )

    return out, errors


def validate_linear_chain(doc: Dict[str, Any], *, initial_artifacts: Optional[List[str]] = None) -> Tuple[bool, List[str]]:
    """Validate that the chain is solvable in the listed order.

    Rule:
    - Each `requires[*].artifact` must be available from either:
      - `initial_artifacts`, OR
      - a prior challenge's `produces[*].artifact`.
    - If `requires[*].source` is set, the artifact must have been produced by that
      specific prior challenge_id.

    Returns: (ok, errors)
    """
    specs, errors = _coerce_challenge_specs(doc)
    if errors:
        return False, errors

    by_id: Dict[str, ChallengeSpec] = {}
    for s in specs:
        if not s.challenge_id:
            continue
        if s.challenge_id in by_id:
            errors.append(f"duplicate challenge_id: {s.challenge_id}")
        by_id[s.challenge_id] = s

    available_any: set[str] = set(str(a).strip() for a in (initial_artifacts or []) if str(a).strip())
    produced_by: Dict[str, set[str]] = {}

    for idx, spec in enumerate(specs):
        cid = spec.challenge_id or f"(index {idx})"

        for req in spec.requires:
            art = req.artifact
            if not art:
                continue
            if req.source:
                src = req.source
                if src not in produced_by:
                    errors.append(f"{cid} requires {art} from {src}, but {src} has not run yet")
                    continue
                if art not in produced_by.get(src, set()):
                    errors.append(f"{cid} requires {art} from {src}, but {src} did not produce it")
                    continue
            else:
                if art not in available_any:
                    errors.append(f"{cid} requires {art}, but it has not been produced by any prior challenge")

        # After validating requirements, add this challenge's outputs.
        prods = set(p.artifact for p in spec.produces if p.artifact)
        produced_by[spec.challenge_id] = prods
        available_any |= prods

    return (not errors), errors
