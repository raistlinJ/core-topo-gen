# AI Generator Workflow

This document explains why the AI Generator has become more reliable recently and how the current workflow turns a free-form model response into a backend-valid scenario preview.

## Core idea

The AI Generator no longer treats the model as the only source of truth.

The current flow is:

1. Read the user prompt and current scenario state.
2. Compile explicit prompt intent into backend-authored section seeds.
3. Let the model fill in the remaining details.
4. Canonicalize and validate the generated scenario.
5. Run preview from the backend planner.
6. Retry with targeted repair guidance when counts or requested values are missing.

That compiler-plus-validator approach is the main reason generation quality improved.

## What changed recently

### 1. Deterministic intent compiler became authoritative

The intent compiler in `core_topo_gen/planning/ai_topology_intent.py` now extracts explicit structured asks from the prompt and converts them into seeded scenario sections.

This covers explicit requests such as:

- total node count
- router count
- host-role counts
- Docker counts
- routing protocol
- traffic/service/segmentation counts
- vulnerability target count

The compiler emits:

- section payloads for backend use
- MCP seed operations for bridge mode

This means both the direct JSON path and the MCP bridge path start from the same deterministic interpretation of the prompt instead of relying on model wording alone.

### 2. Compiler-managed sections now override model drift

For compiler-owned sections, the backend reapplies compiled intent after generation.

That prevents cases where the model says the right thing in prose but returns rows that drift from explicit user requirements. In practice, this sharply reduced errors in:

- router counts
- host totals
- Docker allocation for vulnerabilities
- routing protocol selection
- vulnerability row counts

### 3. Routing protocol requests are preserved

The compiler used to seed router rows with `OSPFv2` by default.

It now respects explicitly requested routing protocols such as:

- `RIP`
- `RIPNG`
- `BGP`
- `OSPFv2`
- `OSPFv3`

This matters because compiler-managed Routing rows are authoritative once applied.

### 4. Vulnerability intent extraction got better

Earlier logic mostly handled prompts like:

- `1 web vulnerability`
- `3 vulnerabilities related to web`

It did not reliably understand list-style requests like:

- `sql injection, web, and another random vulnerability`

The compiler now extracts multiple vulnerability targets from listed phrases when the prompt is clearly in a vulnerability context.

That fixed a common failure mode where the model described multiple vulnerabilities correctly, but the final generated scenario only contained one compiler-seeded vulnerability row.

### 5. Multi-vulnerability prompts now seed distinct rows

For multi-target vulnerability requests, the compiler now searches and seeds multiple concrete `Specific` vulnerability rows instead of collapsing everything to one generalized target.

That improves both:

- the generated scenario payload
- the planner preview shown in the UI

### 6. Prompt coverage checks became a hard feedback loop

The backend route in `webapp/routes/ai_provider.py` now checks whether the generated scenario actually satisfies what the prompt asked for.

Coverage checks look for:

- missing sections
- wrong counts
- missing requested values
- incomplete vulnerability coverage

Examples:

- prompt asked for `RIP` but draft used a different routing protocol
- prompt asked for `TCP` and `UDP` but only one traffic row was present
- prompt implied multiple vulnerabilities but only one was authored

When coverage is incomplete, the backend can retry generation with stricter repair guidance.

### 7. Count mismatch retries became more targeted

The generation flow now distinguishes between:

- preview count mismatches
- prompt coverage mismatches
- recoverable tool failures

That lets the retry prompt focus on the actual problem instead of issuing a generic “try again” request.

This has been especially helpful for prompts that combine:

- total nodes
- router counts
- Docker requirements
- vulnerabilities
- routing density or protocol requirements

### 8. MCP bridge preview now reflects the final scenario

In MCP bridge mode, the returned `generated_scenario` and returned `preview` used to diverge in some cases because preview could come from an earlier draft snapshot.

The bridge flow now refreshes preview from the final canonicalized scenario before returning the result.

That fixed the class of bug where:

- the scenario payload looked correct
- but the topology preview showed extra or stale assignments

### 9. Vulnerability grounding guidance is more count-aware

The vulnerability grounding guidance now uses the requested target count instead of always surfacing several likely matches.

That means:

- singular prompts are guided toward one concrete match
- plural prompts are guided toward the requested number of concrete matches

This reduced over-generation during vulnerability authoring.

### 10. The UI exposes section counts after generation

The frontend now stores and renders per-section item counts after a successful AI generation.

This makes it easier to verify that generation actually produced what the prompt asked for in sections like:

- Routing
- Services
- Traffic
- Vulnerabilities
- Segmentation

## Current backend workflow

### Direct JSON path

1. The user prompt and current scenario are sent to the AI generation route.
2. The compiler derives deterministic intent from the prompt.
3. The provider generates a draft scenario.
4. Compiler-managed sections are reapplied.
5. Vulnerabilities and routing modes are canonicalized.
6. Prompt coverage and preview-count mismatches are checked.
7. If needed, the route retries once or twice with tighter repair instructions.
8. Preview is generated from the final scenario.

### MCP bridge path

1. The backend creates an in-memory draft.
2. The model mutates that draft through `scenario.*` tools.
3. The draft is previewed.
4. The backend fetches the resulting scenario.
5. Compiler-managed sections are reapplied.
6. Vulnerabilities and routing are canonicalized.
7. Prompt coverage and count mismatches are checked.
8. If needed, the prompt is retried with repair guidance.
9. Final preview is recomputed from the final scenario, not an earlier preview snapshot.

## Why the generator feels better now

The improvement is mostly architectural, not just prompt tuning.

The system is now doing four things much better:

1. compile explicit structure from the prompt
2. validate the generated scenario against the prompt
3. repair failures with targeted retries
4. preview the final scenario instead of trusting intermediate state

That combination is much more stable than relying on the LLM alone.

## Files that matter most

- `core_topo_gen/planning/ai_topology_intent.py`
- `webapp/routes/ai_provider.py`
- `webapp/static/ai_generator_workflow.js`
- `webapp/static/ai_generator_panel.js`
- `tests/test_ai_topology_intent.py`
- `tests/test_ai_generator_endpoints.py`

## Practical summary

The AI Generator is more accurate now because explicit prompt structure is compiled into authoritative scenario seeds, model output is checked against that intent, and invalid or incomplete drafts are repaired before the user sees the final preview.