from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
import re

_FACT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*$")


@dataclass(frozen=True)
class FactSignature:
    name: str
    arities: Tuple[int, ...]


_ONT_CACHE: Optional[Tuple[Path, float, Dict[str, Set[int]]]] = None


def _default_ontology_path() -> Path:
    return Path(__file__).resolve().parents[2] / "new-schema" / "fact_ontology_reference.yaml"


def _strip_comment(line: str) -> str:
    if "#" not in line:
        return line
    return line.split("#", 1)[0]


def _parse_fact_line(line: str) -> Optional[Tuple[str, int]]:
    raw = _strip_comment(line).strip()
    if not raw:
        return None
    m = _FACT_RE.match(raw)
    if not m:
        return None
    name = m.group(1).strip()
    args_raw = m.group(2).strip()
    if not args_raw:
        arity = 0
    else:
        parts = [p.strip() for p in args_raw.split(",") if p.strip()]
        arity = len(parts)
    return name, arity


def load_fact_ontology(path: Optional[Path] = None) -> Dict[str, Set[int]]:
    """Load fact signatures from the ontology reference.

    Returns a mapping of fact name -> set of allowed arities.
    """
    global _ONT_CACHE
    p = (path or _default_ontology_path()).resolve()
    try:
        mtime = p.stat().st_mtime
    except FileNotFoundError:
        return {}

    if _ONT_CACHE and _ONT_CACHE[0] == p and _ONT_CACHE[1] == mtime:
        return _ONT_CACHE[2]

    out: Dict[str, Set[int]] = {}
    try:
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                parsed = _parse_fact_line(line)
                if not parsed:
                    continue
                name, arity = parsed
                out.setdefault(name, set()).add(arity)
    except Exception:
        return {}

    _ONT_CACHE = (p, mtime, out)
    return out


def parse_fact_ref(value: str) -> Optional[Tuple[str, int]]:
    """Parse a fact reference like Name(a,b). Returns (name, arity) or None."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    m = _FACT_RE.match(raw)
    if not m:
        return None
    name = m.group(1).strip()
    args_raw = m.group(2).strip()
    if not args_raw:
        return (name, 0)
    parts = [p.strip() for p in args_raw.split(",") if p.strip()]
    return (name, len(parts))


def validate_fact_ref(value: str, *, ontology: Dict[str, Set[int]]) -> Optional[str]:
    """Return an error message if `value` is not a valid fact ref per ontology."""
    parsed = parse_fact_ref(value)
    if not parsed:
        return "must be a FactName(arg1, arg2) reference"
    name, arity = parsed
    allowed = ontology.get(name)
    if not allowed:
        return f"unknown fact '{name}'"
    if arity not in allowed:
        allowed_fmt = ", ".join(str(a) for a in sorted(allowed))
        return f"fact '{name}' expects {allowed_fmt} args, got {arity}"
    return None
