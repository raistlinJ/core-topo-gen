import json
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


BASE = "http://127.0.0.1:9090"
USER = "coreadmin"
PW = "coreadmin"


def _scenario_name_from_xml(xml_path: str) -> str:
    path = Path(str(xml_path or "").strip())
    if not path.exists() or not path.is_file():
        return ""
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return ""
    # Preferred schema: <Scenarios><Scenario name="..."></Scenario></Scenarios>
    scenario_node = root.find(".//Scenario")
    if scenario_node is not None:
        name = str(scenario_node.get("name") or "").strip()
        if name:
            return name
    # Fallback to common lower-case variant.
    scenario_node = root.find(".//scenario")
    if scenario_node is not None:
        name = str(scenario_node.get("name") or "").strip()
        if name:
            return name
    return ""


def _get_default_scenario_and_xml() -> tuple[str, str]:
    catalog_path = Path("outputs/scenario_catalog.json")
    catalog = {}
    if catalog_path.exists():
        try:
            catalog = json.loads(catalog_path.read_text("utf-8"))
        except Exception:
            catalog = {}

    names = catalog.get("names") or []
    scenario = ""
    if names:
        first = names[0]
        scenario = str(first) if first is not None else ""

    xml_map = catalog.get("sources") or {}
    if scenario:
        xml_path = str(xml_map.get(scenario) or "").strip()
        if xml_path and Path(xml_path).exists():
            resolved = str(Path(xml_path).resolve())
            scenario_from_xml = _scenario_name_from_xml(resolved)
            return (scenario_from_xml or scenario), resolved

    for name in names:
        scen_name = str(name) if name is not None else ""
        xml_path = str(xml_map.get(scen_name) or "").strip()
        if xml_path and Path(xml_path).exists():
            resolved = str(Path(xml_path).resolve())
            scenario_from_xml = _scenario_name_from_xml(resolved)
            return (scenario_from_xml or scen_name), resolved

    recent_xml = sorted(
        Path("outputs").glob("scenarios-*/**/*.xml"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if recent_xml:
        resolved = str(recent_xml[0].resolve())
        return _scenario_name_from_xml(resolved), resolved

    return scenario, ""


def main() -> int:
    scenario, xml_path = _get_default_scenario_and_xml()
    run_url = f"{BASE}/"
    params: list[str] = []
    if xml_path:
        params.append(f"xml_path={xml_path}")
    elif scenario:
        params.append(f"scenario={scenario}")
    if params:
        run_url += "?" + "&".join(params)

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
                (forced) => {
                    const forcedScenario = String((forced && forced.scenario) || '').trim();
                    const forcedXmlPath = String((forced && forced.xml_path) || '').trim();
                    const ctx = (typeof getActiveScenarioContext === 'function')
                        ? getActiveScenarioContext()
                        : { idx: 0 };
                    const scenarioIndex = Number.isInteger(ctx?.idx) ? ctx.idx : 0;
                    try {
                        if (Array.isArray(state?.scenarios) && state.scenarios[scenarioIndex]) {
                            const urlXml = (() => {
                                try {
                                    const u = new URL(window.location.href);
                                    return String(u.searchParams.get('xml_path') || '').trim();
                                } catch (e) {
                                    return '';
                                }
                            })();
                            const savedXml = String(
                                state.scenarios[scenarioIndex].saved_xml_path
                                || state.scenarios[scenarioIndex].savedXmlPath
                                || ''
                            ).trim();
                            const preferredXml = (urlXml && urlXml.endsWith('.xml'))
                                ? urlXml
                                : ((savedXml && savedXml.endsWith('.xml')) ? savedXml : '');
                            const effectiveXml = String(forcedXmlPath || preferredXml || '').trim();
                            const effectiveScenario = String(forcedScenario || state.scenarios[scenarioIndex].name || state.result_path_scenario || '').trim();
                            if (effectiveXml) {
                                state.result_path = effectiveXml;
                                state.result_path_scenario = effectiveScenario || state.result_path_scenario || '';
                                try {
                                    state.scenarios[scenarioIndex].saved_xml_path = effectiveXml;
                                    state.scenarios[scenarioIndex].savedXmlPath = effectiveXml;
                                    if (effectiveScenario) {
                                        state.scenarios[scenarioIndex].name = effectiveScenario;
                                        state.scenarios[scenarioIndex].scenario = effectiveScenario;
                                    }
                                } catch (e) {}
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

                    // Ensure UI toggles reflect our intended advanced settings.
                    // The active-session detection prompt path consults these toggles.
                    try {
                        const autoKillEl = document.getElementById('executeAdvAutoKillSessions');
                        if (autoKillEl) autoKillEl.checked = false;
                    } catch (e) { }
                    try {
                        const coreCleanupEl = document.getElementById('executeAdvRunCoreCleanup');
                        if (coreCleanupEl) coreCleanupEl.checked = false;
                    } catch (e) { }
                    try {
                        const dockerCleanupEl = document.getElementById('executeAdvDockerCleanupBeforeRun');
                        if (dockerCleanupEl) dockerCleanupEl.checked = false;
                    } catch (e) { }

                    try {
                        const autoKillEl = document.getElementById('executeAdvAutoKillSessions');
                        const coreCleanupEl = document.getElementById('executeAdvRunCoreCleanup');
                        const dockerCleanupEl = document.getElementById('executeAdvDockerCleanupBeforeRun');
                        window.__smokeToggleState = {
                            autoKill: { exists: !!autoKillEl, checked: !!autoKillEl?.checked },
                            runCoreCleanup: { exists: !!coreCleanupEl, checked: !!coreCleanupEl?.checked },
                            dockerCleanupBeforeRun: { exists: !!dockerCleanupEl, checked: !!dockerCleanupEl?.checked },
                        };
                    } catch (e) {
                        window.__smokeToggleState = { error: String(e) };
                    }
                    try {
                        if (!window.__smokeOriginalBuildRunFormData && typeof buildRunFormData === 'function') {
                            window.__smokeOriginalBuildRunFormData = buildRunFormData;
                            window.buildRunFormData = function (xmlPath, options = {}) {
                                const preferredXml = String(forcedXmlPath || xmlPath || '').trim();
                                const form = window.__smokeOriginalBuildRunFormData(preferredXml || xmlPath, options);
                                try {
                                    if (form && typeof form.set === 'function') {
                                        if (preferredXml) {
                                            form.set('xml_path', preferredXml);
                                        }
                                        if (forcedScenario) {
                                            form.set('scenario', String(forcedScenario));
                                        }
                                        form.set('flow_enabled', '0');
                                    } else if (form && typeof form.append === 'function') {
                                        if (preferredXml) {
                                            form.append('xml_path', preferredXml);
                                        }
                                        if (forcedScenario) {
                                            form.append('scenario', String(forcedScenario));
                                        }
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
                    window.__smokeSecondStarted = false;
                    window.__smokeSecondError = null;
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
                }
                """,
                {'scenario': scenario, 'xml_path': xml_path},
            )

            prompt_seen = False
            prompt_kind = None
            start_abort = None
            second_started = False
            primary_run_id = None
            for _ in range(180):
                if page.locator("text=Active CORE session(s) blocked this run").count() > 0:
                    prompt_seen = True
                    prompt_kind = "blocked"
                    break
                if page.locator("text=Active CORE session(s) detected").count() > 0:
                    prompt_seen = True
                    prompt_kind = "detected"
                    break
                start_abort = page.evaluate("window.__lastRunStartAbort || null")
                run_result = page.evaluate("window.__smokeRunResult")
                run_error = page.evaluate("window.__smokeRunError")
                if run_result is not None or run_error:
                    break
                if start_abort:
                    break

                # If the first run is actively running (has a runProgressRunId), start a second
                # run immediately to force the active-session prompt while the first is in-flight.
                try:
                    current_run_id = page.evaluate("typeof runProgressRunId !== 'undefined' ? runProgressRunId : null")
                except Exception:
                    current_run_id = None
                if current_run_id and not second_started:
                    primary_run_id = current_run_id
                    second_started = True
                    page.evaluate(
                        """
                        (() => {
                            try {
                                if (window.__smokeSecondStarted) return;
                                window.__smokeSecondStarted = true;
                                window.__smokeSecondError = null;
                                // Start a second run attempt while the first is active.
                                // This should trigger active-session detection and a prompt.
                                runSyncWithModal({
                                    showProgressModal: false,
                                    skipConfirm: true,
                                    scenarioIndex: (typeof getActiveScenarioContext === 'function') ? (getActiveScenarioContext()?.idx ?? 0) : 0,
                                    confirmResult: { confirmed: true, scenarioIndex: (typeof getActiveScenarioContext === 'function') ? (getActiveScenarioContext()?.idx ?? 0) : 0, updateRemote: false },
                                    advanced: { autoKillSessions: false, runCoreCleanup: false, dockerCleanupBeforeRun: false },
                                }).catch((e) => {
                                    try { window.__smokeSecondError = String(e && e.message ? e.message : e); } catch (_) { }
                                });
                            } catch (e) {
                                try { window.__smokeSecondError = String(e && e.message ? e.message : e); } catch (_) { }
                            }
                        })();
                        """
                    )
                time.sleep(1)

            if not prompt_seen:
                progress_log = ""
                try:
                    progress_log = page.locator("#executeProgressLog").inner_text(timeout=2000)
                except Exception:
                    progress_log = ""
                toggle_state = None
                try:
                    toggle_state = page.evaluate("window.__smokeToggleState || null")
                except Exception:
                    toggle_state = None
                try:
                    second_debug = page.evaluate("({ started: window.__smokeSecondStarted || false, error: window.__smokeSecondError || null, runId: (typeof runProgressRunId !== 'undefined' ? runProgressRunId : null) })")
                except Exception:
                    second_debug = None
                try:
                    toast_debug = page.evaluate(
                        """
                        (() => {
                            const container = document.getElementById('coretgToastContainer');
                            if (!container) return { exists: false, count: 0, titles: [], bodies: [] };
                            const toasts = Array.from(container.querySelectorAll('.toast'));
                            const titles = toasts.map(t => {
                                const el = t.querySelector('.toast-header strong');
                                return (el && el.textContent) ? String(el.textContent).trim() : '';
                            }).filter(Boolean);
                            const bodies = toasts.map(t => {
                                const el = t.querySelector('.toast-body');
                                return (el && el.textContent) ? String(el.textContent).trim().slice(0, 180) : '';
                            }).filter(Boolean);
                            return { exists: true, count: toasts.length, titles, bodies };
                        })();
                        """
                    )
                except Exception:
                    toast_debug = None
                run_result = page.evaluate("window.__smokeRunResult")
                run_error = page.evaluate("window.__smokeRunError")
                on_complete = page.evaluate("window.__smokeOnComplete")
                on_error = page.evaluate("window.__smokeOnError")
                print(f"prompt_seen=False start_abort={start_abort}")
                print(f"run_result={run_result}")
                print(f"run_error={run_error}")
                print(f"on_complete={on_complete}")
                print(f"on_error={on_error}")
                print(f"toggle_state={toggle_state}")
                print(f"second_debug={second_debug}")
                print(f"toast_debug={toast_debug}")
                print("progress_log_tail_start")
                print((progress_log or "").strip()[-2500:])
                print("progress_log_tail_end")
                return 1

            run_id_before = page.evaluate("typeof runProgressRunId !== 'undefined' ? runProgressRunId : null")

            # There are multiple possible prompt confirm labels depending on where active-session
            # detection occurs (precheck vs. blocked run retry paths).
            if prompt_kind == "blocked":
                confirm_labels = ["Retry with cleanup", "Cleanup & continue", "Kill sessions & retry"]
            else:
                confirm_labels = ["Cleanup & continue", "Kill sessions & retry", "Retry with cleanup"]

            # If we fell back to a native confirm dialog (no Bootstrap toast), the dialog handler
            # above will auto-accept, and there will be no clickable button.
            clicked = False
            clicked_label = None
            for confirm_label in confirm_labels:
                try:
                    page.wait_for_selector(
                        f'button[data-role="confirm"]:has-text("{confirm_label}")',
                        state="visible",
                        timeout=5000,
                    )
                    page.click(f'button[data-role="confirm"]:has-text("{confirm_label}")')
                    clicked = True
                    clicked_label = confirm_label
                    break
                except Exception:
                    continue

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

            blocked_count = page.locator("text=Active CORE session(s) blocked this run").count()
            detected_count = page.locator("text=Active CORE session(s) detected").count()
            print(f"prompt_seen=True kind={prompt_kind} blocked_count={blocked_count} detected_count={detected_count}")
            print(f"retry_click={'ok' if clicked else 'dialog_or_missing_button'}")
            if clicked_label:
                print(f"retry_click_label={clicked_label}")
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
