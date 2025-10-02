# Migration Guide

## 2025 Full Preview Simplification

The project removed the phased builder, approval workflow, plan JSON reuse, and drift/strict-plan modes. Use the unified Full Preview + Run flow.

### Removed
- CLI flags: `--approve-plan`, `--use-plan`, `--strict-plan` (and any implicit phased modes)
- Web endpoints: `/api/plan/approve*`, `/api/plan/status`, any plan build endpoints relying on stored plan JSON
- Builder module: phased builder implementation (`topology_phased` now minimal stub)
- Report section: "Plan Summary (Phased Build)"

### Still Available
- Deterministic builds via `--seed` (CLI) and seed field in Web UI.
- One-shot full preview: `/api/plan/preview_full` returns routers, hosts, services, vulnerabilities, segmentation items, connectivity policies.

### What To Do
| Old Action | New Action |
|------------|-----------|
| Call `/api/plan/approve`, then `/run_with_plan` | Call `/api/plan/preview_full`, then standard Run |
| Reuse stored approved plan JSON | Regenerate full preview each run (optionally reusing the same seed) |
| Rely on drift/strict enforcement | Use seeds and XML version control for reproducibility |

### Code Migration
```python
# Before
from core_topo_gen.builders.topology_phased import build_phased_topology  # (no longer present)

# After
from core_topo_gen.builders.topology import build_segmented_topology
```

### FAQ
**Q: How do I reproduce the exact same topology later?**  
Provide the same seed (CLI: `--seed N`; Web: seed input) with unchanged XML. The full preview output will match (roles, services, vulnerabilities, R2R/R2S policies, segmentation choices). IP addresses and MACs remain deterministic under the same seed.

**Q: I still have scripts passing `--use-plan`. Will they break?**  
Yes—remove these flags. Pass only `--xml` (and optionally `--seed`).

**Q: Can I inject a precomputed full preview?**  
Not directly; the system recomputes quickly. If you need custom injection, open an issue describing the use case.

**Q: Where did strict plan validation go?**  
It depended on diffing against an approved plan snapshot. With that snapshot removed, drift detection was removed. Use `git diff` on XML and consistent seeds.

### Version Control Tips
Commit the XML and (optionally) a small JSON excerpt of the full preview for audit. Avoid storing entire plan JSON as an artifact—it's ephemeral now.

### Deprecation Timeline
- 2025-09: Announcement and stubbing
- 2025-10: Removal completed; stubs raise ImportError with migration hint

### Support
Open a GitHub issue with `migration` label if something blocks adoption.
