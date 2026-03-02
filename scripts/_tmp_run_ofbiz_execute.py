from pathlib import Path
import json
import time
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:9090"
USER = "coreadmin"
PW = "coreadmin"
XML_PATH = str(Path("outputs/scenarios-03-01-26-00-53-08/Anatest.xml").resolve())
SCENARIO = "Anatest"


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_default_timeout(60000)
        page.on("dialog", lambda d: d.accept())

        page.goto(f"{BASE}/login", wait_until="domcontentloaded")
        page.fill('input[name="username"]', USER)
        page.fill('input[name="password"]', PW)
        page.click('button[type="submit"]')
        page.wait_for_load_state("domcontentloaded")

        page.goto(f"{BASE}/?xml_path={XML_PATH}&scenario={SCENARIO}", wait_until="domcontentloaded")
        page.wait_for_function("typeof buildRunFormData === 'function' && typeof RUN_CLI_URL !== 'undefined'")

        scenario_ctx = page.evaluate(
            """
            (wanted) => {
                const scenarios = Array.isArray(state?.scenarios) ? state.scenarios : [];
                const wantedNorm = String(wanted || '').trim().toLowerCase();
                let idx = scenarios.findIndex((s) => String(s?.name || '').trim().toLowerCase() === wantedNorm);
                if (idx < 0) idx = 0;
                const name = String((scenarios[idx] && scenarios[idx].name) || wanted || '');
                return { idx, name, count: scenarios.length };
            }
            """,
            SCENARIO,
        )
        print("scenario_ctx=", json.dumps(scenario_ctx))

        result = page.evaluate(
            """
            async ({ xmlPath, scenarioName, scenarioIndex }) => {
                const form = buildRunFormData(xmlPath, {
                    scenarioName,
                    scenarioIndex,
                    advanced: {
                        autoKillSessions: false,
                        runCoreCleanup: false,
                        dockerCleanupBeforeRun: false,
                    },
                });
                const res = await fetch(RUN_CLI_URL, { method: 'POST', body: form });
                let data = null;
                try {
                    data = await res.json();
                } catch (e) {
                    data = { ok: false, error: 'non-json', status: res.status };
                }
                return { status: res.status, data };
            }
            """,
            {
                "xmlPath": XML_PATH,
                "scenarioName": scenario_ctx.get("name") or SCENARIO,
                "scenarioIndex": int(scenario_ctx.get("idx") or 0),
            },
        )

        print("submit=", json.dumps(result))
        run_id = ((result or {}).get("data") or {}).get("run_id")
        if not run_id:
            print("run_id_missing")
            browser.close()
            return 2

        final = None
        for _ in range(420):
            st = page.evaluate(
                """
                async (rid) => {
                    const r = await fetch(`/run_status/${rid}`);
                    const t = await r.text();
                    let j = null;
                    try {
                        j = JSON.parse(t);
                    } catch (e) {
                        j = { _raw: t.slice(0, 200) };
                    }
                    return { status: r.status, body: j };
                }
                """,
                run_id,
            )
            body = (st or {}).get("body") or {}
            status_val = str(body.get("status") or "")
            done = bool(body.get("done")) or status_val in ("completed", "error", "failed")
            if done:
                final = st
                break
            time.sleep(2)

        print("run_id=", run_id)
        print("final=", json.dumps(final))
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
