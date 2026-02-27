import json
import time
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:9090"


def _dump(label: str, value):
    try:
        print(f"{label}={json.dumps(value, default=str)}")
    except Exception:
        print(f"{label}={value}")


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page()
        page.set_default_timeout(45000)
        page.on("dialog", lambda d: d.accept())
        console = []
        page.on("console", lambda m: console.append(f"{m.type}: {m.text}"))

        try:
            page.goto(f"{BASE}/login", wait_until="domcontentloaded")
            page.fill('input[name="username"]', 'coreadmin')
            page.fill('input[name="password"]', 'coreadmin')
            page.click('button[type="submit"]')
            page.wait_for_load_state("domcontentloaded")

            page.goto(f"{BASE}/", wait_until="domcontentloaded")
            page.wait_for_function("typeof runSyncWithModal === 'function'")

            page.evaluate(
                """
                () => {
                    const ctx = (typeof getActiveScenarioContext === 'function')
                        ? getActiveScenarioContext()
                        : { idx: 0 };
                    const scenarioIndex = Number.isInteger(ctx?.idx) ? ctx.idx : 0;
                    const advanced = {
                        autoKillSessions: false,
                        runCoreCleanup: false,
                        dockerCleanupBeforeRun: false,
                    };
                    window.__diagResult = null;
                    window.__diagError = null;
                    window.__diagStartTs = Date.now();
                    window.__diagPromise = runSyncWithModal({
                        showProgressModal: false,
                        skipConfirm: true,
                        scenarioIndex,
                        confirmResult: {
                            confirmed: true,
                            scenarioIndex,
                            updateRemote: false,
                            advanced,
                        },
                        advanced,
                    }).then((v) => {
                        window.__diagResult = v;
                        return v;
                    }).catch((err) => {
                        window.__diagError = String(err && err.message ? err.message : err);
                        throw err;
                    });
                }
                """
            )

            last_len = 0
            for _ in range(180):
                run_id = page.evaluate("typeof runProgressRunId !== 'undefined' ? runProgressRunId : null")
                diag_err = page.evaluate("window.__diagError")
                last_net = page.evaluate("window.__lastExecuteNetworkFailure || null")
                progress = ""
                try:
                    progress = page.evaluate("(document.getElementById('executeProgressLog') && document.getElementById('executeProgressLog').textContent) || ''")
                except Exception:
                    progress = ""
                if len(progress) > last_len and '[ui][net-fail]' in progress:
                    last_len = len(progress)
                if diag_err:
                    break
                if last_net:
                    break
                if run_id:
                    done = page.evaluate("(executeProgressState && executeProgressState.done) ? true : false")
                    if done:
                        break
                time.sleep(1)

            run_id = page.evaluate("typeof runProgressRunId !== 'undefined' ? runProgressRunId : null")
            diag_err = page.evaluate("window.__diagError")
            diag_result = page.evaluate("window.__diagResult")
            last_net = page.evaluate("window.__lastExecuteNetworkFailure || null")
            progress_tail = page.evaluate("((document.getElementById('executeProgressLog') && document.getElementById('executeProgressLog').textContent) || '').slice(-5000)")

            _dump("run_id", run_id)
            _dump("diag_err", diag_err)
            _dump("diag_result_type", type(diag_result).__name__ if diag_result is not None else None)
            _dump("last_execute_network_failure", last_net)
            print("progress_tail_start")
            print(progress_tail)
            print("progress_tail_end")
            print("console_tail_start")
            for line in console[-20:]:
                print(line)
            print("console_tail_end")
            return 0
        finally:
            try:
                browser.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
