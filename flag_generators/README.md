# Flag Generators

These are small, local program stubs that demonstrate the Flag-Generator contract.

## Contract
Each generator should:
- Accept inputs via CLI args and/or environment variables.
- Create artifacts under an output directory.
- Emit a machine-readable manifest named `outputs.json`.

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
