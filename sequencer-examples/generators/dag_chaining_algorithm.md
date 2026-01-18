# DAG Chaining and Sequencing Algorithm

## Inputs
- Validated generator plugin registry
- Artifact registry
- Challenge instance definitions

## Algorithm Overview

1. Index plugins by produced and required artifacts
2. Validate challenge requirements against plugin capabilities
3. Build a directed graph where edges represent artifact flow
4. Detect cycles (reject if found)
5. Topologically sort challenges
6. Optionally randomize producer selection when multiple exist
7. Execute challenges when required artifacts are available

## Pseudocode

```python
known_artifacts = set()
graph = build_graph(challenges)

order = topological_sort(graph)

for challenge in order:
    if challenge.requires <= known_artifacts:
        outputs = execute_plugin(challenge)
        known_artifacts |= outputs
```

This enables deterministic or randomized valid challenge chains.