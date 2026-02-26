from __future__ import annotations

import json
import os
from typing import Any, Callable

from flask import jsonify, render_template, request, send_file


def register(
    app,
    *,
    get_repo_root: Callable[[], str],
    outputs_dir: Callable[[], str],
    load_run_history: Callable[[], list[dict[str, Any]]],
    derive_summary_from_report: Callable[[str | None], str | None],
    load_summary_counts: Callable[[str | None], dict[str, Any]],
    summary_text_from_counts: Callable[[dict[str, Any]], str],
    current_user_getter: Callable[[], dict[str, Any] | None],
    scenario_catalog_for_user: Callable[..., Any],
    collect_scenario_participant_urls: Callable[..., dict[str, str]],
    normalize_scenario_label: Callable[[Any], str],
    builder_filter_report_scenarios: Callable[..., tuple[list[str], str, Any]],
    filter_history_by_scenario: Callable[[list[dict[str, Any]], str], list[dict[str, Any]]],
    resolve_scenario_display: Callable[[str, list[str], str], str],
    scenario_names_from_xml: Callable[[str | None], list[str]],
    run_history_path: str,
    logger=None,
) -> None:
    """Register report + download routes extracted from app_backend."""

    log = logger or getattr(app, "logger", None)

    @app.route('/download_report')
    def download_report():
        result_path = request.args.get('path')
        try:
            if result_path:
                if (result_path.startswith('"') and result_path.endswith('"')) or (result_path.startswith("'") and result_path.endswith("'")):
                    result_path = result_path[1:-1]
                if result_path.startswith('file://'):
                    result_path = result_path[len('file://'):]
                try:
                    from urllib.parse import unquote
                    result_path = unquote(result_path)
                except Exception:
                    pass
                result_path = os.path.expanduser(result_path)
                result_path = os.path.normpath(result_path)
        except Exception:
            pass

        candidates = []
        if result_path:
            candidates.append(result_path)
            try:
                repo_root = get_repo_root()
                if not os.path.isabs(result_path):
                    candidates.append(os.path.abspath(os.path.join(repo_root, result_path)))
                if result_path.startswith('webapp' + os.sep):
                    candidates.append(os.path.abspath(os.path.join(repo_root, result_path)))
                    candidates.append(os.path.abspath(os.path.join(repo_root, result_path.split(os.sep, 1)[-1])))
                if result_path.startswith('outputs' + os.sep):
                    candidates.append(os.path.abspath(os.path.join(outputs_dir(), result_path.split(os.sep, 1)[-1])))
                rp_norm = os.path.normpath(result_path)
                parts = rp_norm.strip(os.sep).split(os.sep)
                if os.path.isabs(result_path) and 'outputs' in parts:
                    try:
                        idx = parts.index('outputs')
                        tail = os.path.join(*parts[idx+1:]) if idx+1 < len(parts) else ''
                        candidates.append(os.path.join(outputs_dir(), tail))
                    except Exception:
                        pass
                if os.path.isabs(result_path) and 'webapp' in parts:
                    parts_wo = [p for p in parts if p != 'webapp']
                    candidates.append(os.path.sep + os.path.join(*parts_wo))
                try:
                    out_abs = os.path.abspath(outputs_dir())
                    if os.path.isabs(result_path) and 'core-sessions' in parts and not result_path.startswith(out_abs):
                        idx = parts.index('core-sessions')
                        tail = os.path.join(*parts[idx+1:]) if idx+1 < len(parts) else ''
                        candidates.append(os.path.join(out_abs, 'core-sessions', tail))
                except Exception:
                    pass
            except Exception:
                pass

        chosen = None
        for p in candidates:
            if p and os.path.exists(p):
                chosen = p
                break
        if chosen:
            try:
                if log is not None:
                    log.info("[download] serving file: %s", os.path.abspath(chosen))
            except Exception:
                pass
            return send_file(chosen, as_attachment=True)

        try:
            if log is not None:
                log.warning("[download] file not found via direct candidates; requested=%s; candidates=%s", result_path, candidates)
        except Exception:
            pass

        try:
            base_name = os.path.basename(result_path) if result_path else None
            if base_name and base_name.lower().endswith('.xml'):
                candidates_found = []
                root_dir = os.path.join(outputs_dir(), 'core-sessions')
                if os.path.exists(root_dir):
                    for dp, _dn, files in os.walk(root_dir):
                        for fn in files:
                            if fn == base_name:
                                alt = os.path.join(dp, fn)
                                if os.path.exists(alt):
                                    candidates_found.append(alt)
                out_dir = outputs_dir()
                if os.path.exists(out_dir):
                    try:
                        for name in os.listdir(out_dir):
                            if not name.startswith('scenarios-'):
                                continue
                            p = os.path.join(out_dir, name)
                            if not os.path.isdir(p):
                                continue
                            for dp, _dn, files in os.walk(p):
                                for fn in files:
                                    if fn == base_name:
                                        alt = os.path.join(dp, fn)
                                        if os.path.exists(alt):
                                            candidates_found.append(alt)
                    except Exception:
                        pass
                if candidates_found:
                    try:
                        candidates_found.sort(key=lambda p: os.stat(p).st_mtime, reverse=True)
                    except Exception:
                        pass
                    chosen_alt = candidates_found[0]
                    try:
                        if log is not None:
                            log.info("[download] basename match: %s -> %s", base_name, chosen_alt)
                    except Exception:
                        pass
                    return send_file(chosen_alt, as_attachment=True)
        except Exception:
            pass

        try:
            if log is not None:
                log.warning("[download] file not found: %s (candidates=%s)", result_path, candidates)
        except Exception:
            pass
        return "File not found", 404

    @app.route('/reports')
    def reports_page():
        raw = load_run_history()
        enriched = []
        for entry in raw:
            e = dict(entry)
            if not (isinstance(e.get('scenario_names'), list) and e.get('scenario_names')):
                scen = (e.get('scenario_name') or '').strip() if isinstance(e.get('scenario_name'), str) else ''
                if scen:
                    e['scenario_names'] = [scen]
                else:
                    src_xml = e.get('single_scenario_xml_path') or e.get('scenario_xml_path') or e.get('xml_path')
                    names = scenario_names_from_xml(src_xml) if src_xml else []
                    e['scenario_names'] = [names[0]] if isinstance(names, list) and names else []
            session_xml = e.get('session_xml_path') or e.get('post_xml_path')
            if session_xml:
                e['session_xml_path'] = session_xml
            if not e.get('summary_path'):
                derived_summary = derive_summary_from_report(e.get('report_path'))
                if derived_summary:
                    e['summary_path'] = derived_summary
            sn = e.get('scenario_names')
            if not isinstance(sn, list):
                if sn is None:
                    e['scenario_names'] = []
                elif isinstance(sn, str):
                    if '||' in sn:
                        e['scenario_names'] = [s for s in sn.split('||') if s]
                    else:
                        e['scenario_names'] = [s.strip() for s in sn.split(',') if s.strip()]
                else:
                    e['scenario_names'] = []
            if isinstance(e.get('scenario_names'), list) and len(e['scenario_names']) > 1:
                e['scenario_names'] = [e['scenario_names'][0]]
            enriched.append(e)
        enriched = sorted(enriched, key=lambda x: x.get('timestamp', ''), reverse=True)
        user = current_user_getter()
        scenario_names, scenario_paths, scenario_url_hints = scenario_catalog_for_user(enriched, user=user)
        scenario_participant_urls = collect_scenario_participant_urls(scenario_paths, scenario_url_hints)
        participant_url_flags = {
            norm: bool(url)
            for norm, url in scenario_participant_urls.items()
            if isinstance(norm, str) and norm
        }
        scenario_query = request.args.get('scenario', '').strip()
        scenario_norm = normalize_scenario_label(scenario_query)
        scenario_names, scenario_norm, _allowed_norms = builder_filter_report_scenarios(
            scenario_names,
            scenario_norm,
            user=user,
        )
        if scenario_names and not scenario_norm:
            scenario_norm = normalize_scenario_label(scenario_names[0])
        if scenario_norm:
            enriched = filter_history_by_scenario(enriched, scenario_norm)
        for entry in enriched:
            try:
                counts = load_summary_counts(entry.get('summary_path'))
                entry['summary_output'] = summary_text_from_counts(counts)
            except Exception:
                entry['summary_output'] = ''
        scenario_display = resolve_scenario_display(scenario_norm, scenario_names, scenario_query)
        return render_template(
            'reports.html',
            history=enriched,
            scenarios=scenario_names,
            active_scenario=scenario_display,
            participant_url_flags=participant_url_flags,
        )

    @app.route('/reports_data')
    def reports_data():
        raw = load_run_history()
        enriched = []
        for entry in raw:
            e = dict(entry)
            if not (isinstance(e.get('scenario_names'), list) and e.get('scenario_names')):
                scen = (e.get('scenario_name') or '').strip() if isinstance(e.get('scenario_name'), str) else ''
                if scen:
                    e['scenario_names'] = [scen]
                else:
                    src_xml = e.get('single_scenario_xml_path') or e.get('scenario_xml_path') or e.get('xml_path')
                    names = scenario_names_from_xml(src_xml) if src_xml else []
                    e['scenario_names'] = [names[0]] if isinstance(names, list) and names else []
            session_xml = e.get('session_xml_path') or e.get('post_xml_path')
            if session_xml:
                e['session_xml_path'] = session_xml
            if not e.get('summary_path'):
                derived_summary = derive_summary_from_report(e.get('report_path'))
                if derived_summary:
                    e['summary_path'] = derived_summary
            sn = e.get('scenario_names')
            if not isinstance(sn, list):
                if sn is None:
                    e['scenario_names'] = []
                elif isinstance(sn, str):
                    if '||' in sn:
                        e['scenario_names'] = [s for s in sn.split('||') if s]
                    else:
                        e['scenario_names'] = [s.strip() for s in sn.split(',') if s.strip()]
                else:
                    e['scenario_names'] = []
            if isinstance(e.get('scenario_names'), list) and len(e['scenario_names']) > 1:
                e['scenario_names'] = [e['scenario_names'][0]]
            try:
                counts = load_summary_counts(e.get('summary_path'))
                e['summary_output'] = summary_text_from_counts(counts)
            except Exception:
                e['summary_output'] = ''
            enriched.append(e)
        enriched = sorted(enriched, key=lambda x: x.get('timestamp', ''), reverse=True)
        user = current_user_getter()
        scenario_names, scenario_paths, scenario_url_hints = scenario_catalog_for_user(enriched, user=user)
        scenario_participant_urls = collect_scenario_participant_urls(scenario_paths, scenario_url_hints)
        participant_url_flags = {
            norm: bool(url)
            for norm, url in scenario_participant_urls.items()
            if isinstance(norm, str) and norm
        }
        scenario_query = request.args.get('scenario', '').strip()
        scenario_norm = normalize_scenario_label(scenario_query)
        scenario_names, scenario_norm, _allowed_norms = builder_filter_report_scenarios(
            scenario_names,
            scenario_norm,
            user=user,
        )
        if scenario_names and not scenario_norm:
            scenario_norm = normalize_scenario_label(scenario_names[0])
        if scenario_norm:
            enriched = filter_history_by_scenario(enriched, scenario_norm)
        scenario_display = resolve_scenario_display(scenario_norm, scenario_names, scenario_query)
        return jsonify({
            'history': enriched,
            'scenarios': scenario_names,
            'active_scenario': scenario_display,
            'participant_url_flags': participant_url_flags,
        })

    @app.route('/reports/delete', methods=['POST'])
    def reports_delete():
        try:
            payload = request.get_json(force=True, silent=True) or {}
            run_ids = payload.get('run_ids') or []
            if not isinstance(run_ids, list):
                return jsonify({'error': 'run_ids must be a list'}), 400
            run_ids_set = set([str(x) for x in run_ids if x])
            if not run_ids_set:
                return jsonify({'deleted': 0})
            history = load_run_history()
            kept = []
            deleted_count = 0
            out_dir = outputs_dir()
            for entry in history:
                rid = str(entry.get('run_id') or '')
                rid_fallback = "|".join([
                    str(entry.get('timestamp') or ''),
                    str(entry.get('scenario_xml_path') or entry.get('xml_path') or ''),
                    str(entry.get('report_path') or ''),
                    str(entry.get('full_scenario_path') or ''),
                ])
                if (rid and rid in run_ids_set) or (rid_fallback and rid_fallback in run_ids_set):
                    for key in ('full_scenario_path', 'scenario_xml_path', 'pre_xml_path', 'post_xml_path', 'xml_path', 'single_scenario_xml_path'):
                        p = entry.get(key)
                        if not p:
                            continue
                        try:
                            ap = os.path.abspath(p)
                            if ap.startswith(os.path.abspath(out_dir)) and os.path.exists(ap):
                                try:
                                    os.remove(ap)
                                    if log is not None:
                                        log.info("[reports.delete] removed %s", ap)
                                except IsADirectoryError:
                                    if log is not None:
                                        log.warning("[reports.delete] skipping directory %s", ap)
                        except Exception as e:
                            if log is not None:
                                log.warning("[reports.delete] error removing %s: %s", p, e)
                    deleted_count += 1
                else:
                    kept.append(entry)

            os.makedirs(os.path.dirname(run_history_path), exist_ok=True)
            tmp = run_history_path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(kept, f, indent=2)
            os.replace(tmp, run_history_path)
            return jsonify({'deleted': deleted_count})
        except Exception as e:
            try:
                if log is not None:
                    log.exception("[reports.delete] failed: %s", e)
            except Exception:
                pass
            return jsonify({'error': 'internal error'}), 500
