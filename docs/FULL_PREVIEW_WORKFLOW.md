# Full Preview Workflow

1. **Save XML** – The editor auto-saves, but hitting “Save XML” ensures consistent previews.
2. **(Optional) Set seed** – Enter an integer seed to get deterministic topology output.
3. **Generate Full Preview** – Shows router/host counts, R2R/R2S policies, segmentation, services, traffic, and vulnerability assignments before any CORE call.
4. **Review structured sections** – Toggle between structured cards and raw JSON; history stores the last 25 previews in local storage.
5. **Run (Seed)** – Launches the CLI asynchronously, streams logs into the dock, and writes a Markdown report to `./reports/`.
