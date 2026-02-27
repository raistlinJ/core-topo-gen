# Flag Generators

These are small, local program stubs that demonstrate the Flag-Generator contract.

> Note: the current production authoring path is manifest-based generator packs. See:
> - [docs/GENERATOR_AUTHORING.md](../docs/GENERATOR_AUTHORING.md)
> - [docs/AI_PROMPT_TEMPLATES.md](../docs/AI_PROMPT_TEMPLATES.md)

## Contract
Each generator should:
- Accept inputs via CLI args and/or environment variables.
- Create artifacts under an output directory.
- Emit a machine-readable manifest named `outputs.json`.
- Keep shared imports (`json`, `sys`, etc.) at module scope when using nested helpers.
- Be validated in both local Test and full Execute paths before release.

For modern authoring, prefer manifest-based scaffolding and AI templates:
- [docs/AI_PROMPT_TEMPLATES.md](../docs/AI_PROMPT_TEMPLATES.md)
- [docs/GENERATOR_AUTHORING.md](../docs/GENERATOR_AUTHORING.md)

Minimum parity checklist:
- `outputs.json` includes `generator_id` and `Flag(flag_id)`
- `outputs.json.outputs` keys match manifest `artifacts.produces`
- optional inputs are explicitly marked `required: false` in manifest
- no runtime dependence on internet/package-manager success

Current stubs emit:

```json
{
  "generator_id": "gen.example",
  "outputs": {
    "key": "value"
  }
}
```

## Examples

Python:
- `python flag_generators/py_basic_artifact/generator.py --seed demo --out-dir /tmp/fg_py_basic`

C:
- `make -C flag_generators/c_basic_binary OUT_DIR=/tmp/fg_c_basic`
- `SECRET=demo /tmp/fg_c_basic/basicbin`

C++:
- `make -C flag_generators/cpp_basic_binary OUT_DIR=/tmp/fg_cpp_basic`
- `SEED=demo /tmp/fg_cpp_basic/basiccpp`
