import json
import time
from pathlib import Path

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


BASE = "http://127.0.0.1:9090"
USER = "coreadmin"
PW = "coreadmin"


def _get_default_scenario_and_xml() -> tuple[str, str]:
    catalog_path = Path("outputs/scenario_catalog.json")
    if not catalog_path.exists():
        return "", ""
    try:
        catalog = json.loads(catalog_path.read_text("utf-8"))
    except Exception:
        return "", ""
    names = catalog.get("names") or []
    if not names:
        return "", ""
    first = names[0]
    scenario = str(first) if first is not None else ""
    xml_map = catalog.get("sources") or {}
    xml_path = str(xml_map.get(scenario) or "").strip()
    return scenario, xml_path


def main() -> int:
    scenario, xml_path = _get_default_scenario_and_xml()
    run_url = f"{BASE}/?auto_execute=1"
    if scenario:
        run_url += f"&scenario={scenario}"
    if xml_path:
        run_url += f"&xml_path={xml_path}"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_default_timeout(45000)
        page.on("dialog", lambda dialog: dialog.accept())
        try:
            page.goto(f"{BASE}/login", wait_until="domcontentloaded")
            page.fill('input[name="username"]', USER)
            page.fill('input[name="password"]', PW)
            page.click('button[type="submit"]')
            page.wait_for_load_state("domcontentloaded")

            page.goto(run_url, wait_until="domcontentloaded")

            page.wait_for_function("typeof runSyncWithModal === 'function'")
            page.evaluate(
                """
                (() => {
                    const ctx = (typeof getActiveScenarioContext === 'function')
                        ? getActiveScenarioContext()
                        : { idx: 0 };
                    const scenarioIndex = Number.isInteger(ctx?.idx) ? ctx.idx : 0;
                    try {
                        if (Array.isArray(state?.scenarios) && state.scenarios[scenarioIndex]) {
                            const savedXml = String(
                                state.scenarios[scenarioIndex].saved_xml_path
                                || state.scenarios[scenarioIndex].savedXmlPath
                                || ''
                            ).trim();
                            if (savedXml && savedXml.endsWith('.xml')) {
                                state.result_path = savedXml;
                                state.result_path_scenario = state.scenarios[scenarioIndex].name || state.result_path_scenario || '';
                            }
                            state.scenarios[scenarioIndex].flow_enabled = false;
                            if (state.scenarios[scenarioIndex].flow && typeof state.scenarios[scenarioIndex].flow === 'object') {
                                state.scenarios[scenarioIndex].flow.enabled = false;
                            }
                            if (state.scenarios[scenarioIndex].hitl && typeof state.scenarios[scenarioIndex].hitl === 'object') {
                                state.scenarios[scenarioIndex].hitl.flow_enabled = false;
                            }
                        }
                    } catch (e) {}
                    const advanced = {
                        autoKillSessions: false,
                        runCoreCleanup: false,
                        dockerCleanupBeforeRun: false,
                    };
                    try {
                        if (!window.__smokeOriginalBuildRunFormData && typeof buildRunFormData === 'function') {
                            window.__smokeOriginalBuildRunFormData = buildRunFormData;
                            window.buildRunFormData = function (xmlPath, options = {}) {
                                const form = window.__smokeOriginalBuildRunFormData(xmlPath, options);
                                try {
                                    if (form && typeof form.set === 'function') {
                                        form.set('flow_enabled', '0');
                                    } else if (form && typeof form.append === 'function') {
                                        form.append('flow_enabled', '0');
                                    }
                                } catch (e) {}
                                return form;
                            };
                        }
                    } catch (e) {}
                    window.__smokeOnComplete = null;
                    window.__smokeOnError = null;
                    window.__smokeRunResult = null;
                    window.__smokeRunError = null;
                    window.__smokeRunPromise = runSyncWithModal({
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
                        onComplete: (data) => {
                            try { window.__smokeOnComplete = data || null; } catch (e) {}
                        },
                        onError: (err) => {
                            try { window.__smokeOnError = String(err && err.message ? err.message : err); } catch (e) {}
                        },
                    }).then((result) => {
                        window.__smokeRunResult = result;
                        return result;
                    }).catch((err) => {
                        window.__smokeRunError = String(err && err.message ? err.message : err);
                        throw err;
                    });
                })();
                """
            )

            prompt_seen = False
            start_abort = None
            for _ in range(120):
                if page.locator("text=Active CORE session(s) blocked this run").count() > 0:
                    prompt_seen = True
                    break
                start_abort = page.evaluate("window.__lastRunStartAbort || null")
                run_result = page.evaluate("window.__smokeRunResult")
                run_error = page.evaluate("window.__smokeRunError")
                if run_result is not None or run_error:
                    break
                if start_abort:
                    break
                time.sleep(1)

            if not prompt_seen:
                progress_log = ""
                try:
                    progress_log = page.locator("#executeProgressLog").inner_text(timeout=2000)
                except Exception:
                    progress_log = ""
                run_result = page.evaluate("window.__smokeRunResult")
                run_error = page.evaluate("window.__smokeRunError")
                on_complete = page.evaluate("window.__smokeOnComplete")
                on_error = page.evaluate("window.__smokeOnError")
                print(f"prompt_seen=False start_abort={start_abort}")
                print(f"run_result={run_result}")
                print(f"run_error={run_error}")
                print(f"on_complete={on_complete}")
                print(f"on_error={on_error}")
                print("progress_log_tail_start")
                print((progress_log or "").strip()[-2500:])
                print("progress_log_tail_end")
                return 1

            run_id_before = page.evaluate("typeof runProgressRunId !== 'undefined' ? runProgressRunId : null")
            page.wait_for_selector('button[data-role="confirm"]:has-text("Retry with cleanup")', state="visible")
            page.click('button[data-role="confirm"]:has-text("Retry with cleanup")')
            page.wait_for_function(
                """
                (beforeId) => {
                    try {
                        const currentId = (typeof runProgressRunId !== 'undefined') ? runProgressRunId : null;
                        return !!currentId && currentId !== beforeId;
                    } catch (e) {
                        return false;
                    }
                }
                """,
                arg=run_id_before,
                timeout=120000,
            )
            run_id_after = page.evaluate("typeof runProgressRunId !== 'undefined' ? runProgressRunId : null")

            prompt_count = page.locator("text=Active CORE session(s) blocked this run").count()
            print(f"prompt_seen=True count={prompt_count}")
            print("retry_click=ok")
            print(f"retry_run_id_before={run_id_before}")
            print(f"retry_run_id_after={run_id_after}")
            return 0
        except PlaywrightTimeoutError as exc:
            print(f"timeout_error={exc}")
            return 1
        except Exception as exc:
            print(f"error={exc}")
            return 1
        finally:
            try:
                browser.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
