# Changelog

All notable changes to this project will be documented in this file.

The format loosely follows Keep a Changelog and semantic versioning (when practical).

## [0.3.0] - 2025-09-26
### Added
- Router connectivity policies: per-routing-item `r2r_mode` (Uniform / NonUniform / Exact / Min / Random) with global mesh style fallback (`full`, `ring`, `tree`).
- Router-to-Switch aggregation: `r2s_mode` + `r2s_edges` attributes; hosts rehomed behind aggregation switches; report includes aggregation stats.
- Advanced connectivity metrics in report: router degree min/max/avg/std/Gini; aggregation switch host distribution stats; rehomed host counts.
- Additive router planning semantics (density + abs_count) with absolute density when `density > 1`.
- Default base host pool when unspecified now 10 (was 8). Explicit zero requires `0` entry.
- Vulnerability assignment lenient mode (allows planning with downloaded-but-not-pulled items).
- `--router-mesh-style` CLI flag for fallback when no per-item `r2r_mode` is defined.
- Planning metadata integration: merged into report (namespaced `plan_*` keys) and exposed via `/planning_meta` endpoint.
- CHANGELOG introduced and package `__version__` set to `0.3.0`.

### Changed
- Routing builder logic: additive instead of count-only precedence when both density and absolute counts present.
- Mesh style implementations (ring/tree) made exact (no surplus links); ring uses budgeted edge additions.
- README & API docs expanded with connectivity, aggregation, and planning default clarifications.

### Fixed
- Legacy tests updated to align with new default base=10.
- Router count calculation now stable for absolute density values (e.g., `density=5`).
- Environment TOML test normalization of `repo/` path prefixes.
- Dockerfile lint test now skips gracefully if `hadolint` not installed.
- Indentation issues in several legacy test files corrected.

### Removed / Deprecated
- Implicit interpretation of blank base host value as 0 (now defaults to 10 unless explicitly set to 0).
- Old behavior where count-based router rows suppressed density contribution.

## [0.2.x] - 2025-08 to 2025-09
- Prior iterative improvements to scenario editing, vulnerability catalog handling, segmentation and traffic generation (see git history for granular commits).

## [0.1.x] - Initial development
- Basic XML parsing, star/segmented topology generation, services & traffic script generation, report output.

---

Release process reminder:
1. Update `__version__` in `core_topo_gen/__init__.py`.
2. Update this CHANGELOG with a new section.
3. Tag commit: `git tag -a v<version> -m "Release <version>"` and push tags.
4. (Optional) Build & publish distribution artifacts.
