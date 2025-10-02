# Changelog

All notable changes to this project will be documented in this file.

The format loosely follows Keep a Changelog and semantic versioning (when practical).

## [0.3.0] - 2025-09-26
### Added

### Changed

### Fixed

### Removed / Deprecated
- Unified planning orchestrator (`compute_full_plan`) now drives both Web preview and CLI `--preview/--preview-full` paths.
- CLI preview output includes `orchestrator_plan` with full breakdowns (nodes, routers, services, vulnerabilities, segmentation, traffic).
- Web `/api/plan/preview_full` response extended with `breakdowns` and `router_plan` for logging parity.
- Parity test (`test_orchestrator_parity.py`) ensures router plan presence (skips if CORE gRPC not installed).

### Changed
- CLI no longer re-parses vulnerabilities/segmentation for planning when orchestrator data present; reuses raw items.
- Report vulnerability and segmentation sections source data from orchestrator outputs for consistency.

- Implicit interpretation of blank base host value as 0 (now defaults to 10 unless explicitly set to 0).
- Eliminated divergence between preview router counts and CLI counts (single source of truth in router_plan).
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
