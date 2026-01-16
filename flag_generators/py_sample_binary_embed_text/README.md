# Sample: Binary Embed Text

This sample **flag-generator** writes an **x64 (amd64) Linux ELF** binary under `outputs/artifacts/` and returns its relative path as:

- `outputs.json.outputs.filesystem.file = "artifacts/<filename>"`

The flag is embedded inside the binary as a static string so it can be recovered with tools like `strings` or a reverse engineering tool (e.g., Ghidra).

## Inputs

All inputs are optional and provided via `inputs/config.json`:

- `seed` (text): used to deterministically derive a flag and default filename.
- `filesystem.file` (text): optional output binary filename (or relative path like `artifacts/<name>`); if omitted, a deterministic random-looking name is derived from `seed`.
	- Legacy alias: `filename`.
- `flag` (text): optional explicit flag value to embed; if omitted, a deterministic flag is derived from `seed`.

## Outputs

- `flag` (text): the expected flag value (sensitive).
- `filesystem.file` (file): relative path to the generated binary under `outputs/`.

## Notes

- The container is pinned to `linux/amd64` to ensure an x64 binary is produced even on ARM hosts.
- The binary prints a decoy value and does not print the flag.
