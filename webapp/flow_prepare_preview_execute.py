from __future__ import annotations

import json
import os
import sys
import time
import uuid
from types import SimpleNamespace

from flask import current_app, jsonify, request
from typing import Any, Dict


def _backend_dependencies(backend: Any) -> Any:
    bound_names = [
        '_coerce_bool',
        '_normalize_scenario_label',
        '_flow_preset_steps',
        '_existing_xml_path_or_none',
        '_planner_get_plan',
        '_latest_preview_plan_for_scenario_norm_origin',
        '_latest_preview_plan_for_scenario_norm',
        '_core_config_from_xml_path',
        '_load_run_history',
        '_select_core_config_for_page',
        '_merge_core_configs',
        '_apply_core_secret_to_config',
        '_flow_normalize_fact_override',
        '_load_preview_payload_from_path',
        '_canonicalize_payload_flow_from_xml',
        '_build_topology_graph_from_preview_plan',
        '_flow_compose_docker_stats',
        '_flow_compute_flag_assignments_for_preset',
        '_flow_compute_flag_assignments',
        '_flow_reorder_chain_by_generator_dag',
        '_flag_generators_from_enabled_sources',
        '_flag_node_generators_from_enabled_sources',
        '_flow_validate_chain_order_by_requires_produces',
        '_flow_required_installed_generator_outputs',
        '_get_repo_root',
        '_flow_required_generator_repo_paths',
        '_push_repo_to_remote',
        '_require_core_ssh_credentials',
        '_open_ssh_client',
        '_remote_static_repo_dir',
        '_remote_path_join',
        '_flow_node_is_vuln',
        '_flow_node_is_docker_role',
        '_outputs_dir',
        '_local_timestamp_safe',
        '_enrich_flow_state_with_artifacts',
        '_flow_strip_runtime_sensitive_fields',
        '_canonicalize_flow_assignment_paths',
        '_abs_path_or_original',
        '_iso_now',
    ]
    return SimpleNamespace(**{name: getattr(backend, name) for name in bound_names})


def _prepare_remote_generator_execution(
    deps,
    *,
    run_generators: bool,
    flow_run_remote: bool,
    flow_remote_forced: bool,
    flow_core_cfg: Dict[str, Any] | None,
    flag_assignments: list[dict[str, Any]] | None,
    flow_progress,
) -> dict[str, Any]:
    flow_remote_repo_dir: str | None = None
    if not (run_generators and flow_run_remote):
        return {
            'flow_run_remote': flow_run_remote,
            'flow_core_cfg': flow_core_cfg,
            'flow_remote_repo_dir': flow_remote_repo_dir,
            'response': None,
        }

    if isinstance(flow_core_cfg, dict):
        try:
            current_app.logger.info('[flow.generator] syncing repo to CORE VM before remote generator run')
        except Exception:
            pass
        allowed_outputs_override = None
        include_repo_paths = None
        try:
            allowed_outputs_override = deps._flow_required_installed_generator_outputs(
                flag_assignments,
                repo_root=deps._get_repo_root(),
            )
            include_repo_paths = deps._flow_required_generator_repo_paths(
                flag_assignments,
                repo_root=deps._get_repo_root(),
            )
            if not include_repo_paths:
                raise ValueError('No generator paths resolved for Flow sync.')
            try:
                generator_only = [
                    path for path in (allowed_outputs_override or [])
                    if path.startswith('outputs/installed_generators/')
                ]
            except Exception:
                generator_only = []

            if generator_only:
                try:
                    include_repo_paths = list(dict.fromkeys([*(include_repo_paths or []), *generator_only]))
                except Exception:
                    pass
            if generator_only:
                current_app.logger.info('[flow.generator] Syncing repo to CORE VM (generators: %d)', len(generator_only))
            else:
                current_app.logger.info('[flow.generator] Syncing repo to CORE VM (no installed generators needed)')
        except Exception as exc:
            current_app.logger.error('[flow.generator] failed to resolve generator paths: %s', exc, exc_info=True)
            allowed_outputs_override = None
            include_repo_paths = None
        try:
            if not allowed_outputs_override:
                current_app.logger.info('[flow.generator] Syncing repo to CORE VM (reduced snapshot)')
        except Exception:
            pass
        try:
            if not include_repo_paths:
                current_app.logger.info('[flow.generator] repo sync skipped (no generator paths resolved)')
            else:
                deps._push_repo_to_remote(
                    flow_core_cfg,
                    logger=current_app.logger,
                    upload_only_injected_artifacts=True,
                    allowed_outputs_override=allowed_outputs_override,
                    include_repo_paths=include_repo_paths,
                )
                try:
                    flow_progress('Repo sync complete')
                except Exception:
                    pass
        except Exception as exc:
            if flow_remote_forced:
                return {
                    'flow_run_remote': flow_run_remote,
                    'flow_core_cfg': flow_core_cfg,
                    'flow_remote_repo_dir': flow_remote_repo_dir,
                    'response': (jsonify({'ok': False, 'error': f'Failed to sync repo to CORE VM: {exc}'}), 500),
                }
            try:
                current_app.logger.warning('[flow.generator] repo sync failed (continuing): %s', exc)
            except Exception:
                pass

    if not isinstance(flow_core_cfg, dict):
        if flow_remote_forced:
            return {
                'flow_run_remote': flow_run_remote,
                'flow_core_cfg': flow_core_cfg,
                'flow_remote_repo_dir': flow_remote_repo_dir,
                'response': (jsonify({'ok': False, 'error': 'Remote Flow generation requested but no CORE VM config was found.'}), 400),
            }
        return {
            'flow_run_remote': False,
            'flow_core_cfg': flow_core_cfg,
            'flow_remote_repo_dir': flow_remote_repo_dir,
            'response': None,
        }

    try:
        flow_core_cfg = deps._require_core_ssh_credentials(flow_core_cfg)
    except Exception as exc:
        if flow_remote_forced:
            return {
                'flow_run_remote': flow_run_remote,
                'flow_core_cfg': flow_core_cfg,
                'flow_remote_repo_dir': flow_remote_repo_dir,
                'response': (jsonify({'ok': False, 'error': f'Remote Flow generation requires SSH credentials: {exc}'}), 400),
            }
        return {
            'flow_run_remote': False,
            'flow_core_cfg': flow_core_cfg,
            'flow_remote_repo_dir': flow_remote_repo_dir,
            'response': None,
        }

    client = None
    sftp = None
    try:
        client = deps._open_ssh_client(flow_core_cfg)
        sftp = client.open_sftp()
        flow_remote_repo_dir = deps._remote_static_repo_dir(sftp)
        runner_path = deps._remote_path_join(flow_remote_repo_dir, 'scripts', 'run_flag_generator.py')
        sftp.stat(flow_remote_repo_dir)
        sftp.stat(runner_path)
    except Exception as exc:
        if flow_remote_forced:
            return {
                'flow_run_remote': flow_run_remote,
                'flow_core_cfg': flow_core_cfg,
                'flow_remote_repo_dir': flow_remote_repo_dir,
                'response': (jsonify({'ok': False, 'error': f'Remote Flow generation requires repo on CORE VM: {exc}'}), 400),
            }
        flow_run_remote = False
        flow_remote_repo_dir = None
    finally:
        try:
            if sftp:
                sftp.close()
        except Exception:
            pass
        try:
            if client:
                client.close()
        except Exception:
            pass

    return {
        'flow_run_remote': flow_run_remote,
        'flow_core_cfg': flow_core_cfg,
        'flow_remote_repo_dir': flow_remote_repo_dir,
        'response': None,
    }


def _load_prepare_preview_request_context(*, deps, flow_progress) -> dict[str, Any]:
    j = request.get_json(silent=True) or {}
    with open('/tmp/app_backend_debug.txt', 'a') as f:
        f.write(f"DEBUG: api_flow_prepare_preview_for_execute called. j={list(j.keys())}\n")
    scenario_label = str(j.get('scenario') or '').strip()
    scenario_norm = deps._normalize_scenario_label(scenario_label)
    preset = str(j.get('preset') or '').strip()
    mode = str(j.get('mode') or '').strip().lower()
    best_effort = bool(j.get('best_effort')) or (mode in {'hint', 'hint_only', 'resolve_hints', 'preview'})
    run_generators_request = bool(mode in {'resolve', 'resolve_hints', 'hint', 'hint_only'})
    cleanup_generated_artifacts = deps._coerce_bool(j.get('cleanup_generated_artifacts'))
    allow_node_duplicates = str(j.get('allow_node_duplicates') or j.get('allow_duplicates') or '').strip().lower() in ('1', 'true', 'yes', 'y')
    total_timeout_s: int | None = None
    try:
        total_timeout_s = int(j.get('timeout_s') or 0)
    except Exception:
        total_timeout_s = None
    if total_timeout_s is not None and total_timeout_s <= 0:
        total_timeout_s = None
    if best_effort and total_timeout_s is None:
        total_timeout_s = 30
    try:
        length = int(j.get('length') or 5)
    except Exception:
        length = 5
    preset_steps = deps._flow_preset_steps(preset)
    if preset_steps:
        length = len(preset_steps)
    length = max(1, min(length, 50))
    requested_length = length

    if not scenario_norm:
        return {
            'response': (jsonify({'ok': False, 'error': 'No scenario specified.'}), 400),
        }

    flow_run_remote = False
    flow_remote_forced = False
    flow_core_cfg: Dict[str, Any] | None = None
    try:
        if 'run_remote' in j:
            flow_run_remote = deps._coerce_bool(j.get('run_remote'))
            flow_remote_forced = flow_run_remote
        if 'run_local' in j and deps._coerce_bool(j.get('run_local')):
            flow_run_remote = False
            flow_remote_forced = False
    except Exception:
        pass

    base_plan_path = str(j.get('preview_plan') or '').strip() or None
    if base_plan_path:
        base_plan_path = deps._existing_xml_path_or_none(base_plan_path)
    if not base_plan_path:
        try:
            entry = deps._planner_get_plan(scenario_norm)
            if entry:
                base_plan_path = (
                    deps._existing_xml_path_or_none(entry.get('plan_path'))
                    or deps._existing_xml_path_or_none(entry.get('xml_path'))
                    or base_plan_path
                )
        except Exception:
            base_plan_path = base_plan_path

    if not base_plan_path:
        base_plan_path = deps._latest_preview_plan_for_scenario_norm_origin(scenario_norm, origin='planner')

    if not base_plan_path:
        base_plan_path = deps._latest_preview_plan_for_scenario_norm(scenario_norm)

    if not base_plan_path:
        return {
            'response': (jsonify({'ok': False, 'error': 'No preview plan found for this scenario. Generate a Full Preview first.'}), 404),
        }

    try:
        flow_core_cfg = deps._core_config_from_xml_path(base_plan_path, scenario_norm, include_password=True)
        explicit_core_host = ''
        explicit_core_port = None
        if isinstance(flow_core_cfg, dict):
            explicit_core_host = str(flow_core_cfg.get('grpc_host') or flow_core_cfg.get('host') or '').strip()
            raw_port = flow_core_cfg.get('grpc_port') if flow_core_cfg.get('grpc_port') not in (None, '') else flow_core_cfg.get('port')
            try:
                explicit_core_port = int(raw_port) if raw_port not in (None, '') else None
            except Exception:
                explicit_core_port = None

            page_core_cfg = None
            try:
                page_core_cfg = deps._select_core_config_for_page(scenario_norm, include_password=True)
            except TypeError:
                try:
                    history = deps._load_run_history()
                except Exception:
                    history = None
                try:
                    page_core_cfg = deps._select_core_config_for_page(scenario_norm, history, include_password=True)
                except Exception:
                    page_core_cfg = None
            except Exception:
                page_core_cfg = None

            if isinstance(page_core_cfg, dict) and page_core_cfg:
                merged_core_cfg = dict(flow_core_cfg)

                page_password = page_core_cfg.get('ssh_password')
                if merged_core_cfg.get('ssh_password') in (None, '') and page_password not in (None, ''):
                    merged_core_cfg['ssh_password'] = page_password

                for field in (
                    'ssh_username',
                    'ssh_port',
                    'venv_bin',
                    'core_secret_id',
                    'vm_key',
                    'vm_name',
                    'vm_node',
                    'vmid',
                    'proxmox_secret_id',
                    'proxmox_target',
                    'validated',
                    'last_tested_status',
                ):
                    if merged_core_cfg.get(field) in (None, '', 0, {}):
                        value = page_core_cfg.get(field)
                        if value not in (None, '', 0, {}):
                            merged_core_cfg[field] = value

                def _is_loopback_host(value: Any) -> bool:
                    try:
                        text = str(value or '').strip().lower()
                    except Exception:
                        return False
                    return text in {'localhost', '127.0.0.1', '::1'}

                page_ssh_host = page_core_cfg.get('ssh_host')
                if page_ssh_host not in (None, ''):
                    current_ssh_host = merged_core_cfg.get('ssh_host')
                    if current_ssh_host in (None, '') or _is_loopback_host(current_ssh_host):
                        merged_core_cfg['ssh_host'] = page_ssh_host

                flow_core_cfg = merged_core_cfg

            flow_core_cfg = deps._apply_core_secret_to_config(flow_core_cfg, scenario_norm)
            if explicit_core_host:
                flow_core_cfg['host'] = explicit_core_host
                flow_core_cfg['grpc_host'] = explicit_core_host
            if explicit_core_port is not None and explicit_core_port > 0:
                flow_core_cfg['port'] = explicit_core_port
                flow_core_cfg['grpc_port'] = explicit_core_port
    except Exception:
        flow_core_cfg = None
    if not flow_remote_forced and isinstance(flow_core_cfg, dict) and deps._coerce_bool(flow_core_cfg.get('ssh_enabled')):
        flow_run_remote = True
    if flow_run_remote and not isinstance(flow_core_cfg, dict):
        return {
            'response': (jsonify({'ok': False, 'error': 'No CoreConnection configured in XML for this scenario.'}), 404),
        }

    initial_facts_override: dict[str, list[str]] | None = None
    goal_facts_override: dict[str, list[str]] | None = None
    try:
        initial_facts_override = deps._flow_normalize_fact_override(j.get('initial_facts'))
        goal_facts_override = deps._flow_normalize_fact_override(j.get('goal_facts'))
    except Exception:
        initial_facts_override = None
        goal_facts_override = None

    started_at = time.monotonic()
    try:
        plan_basename = os.path.basename(base_plan_path)
    except Exception:
        plan_basename = str(base_plan_path or '')
    current_app.logger.info(
        '[flow.prepare_preview_for_execute] start scenario=%s requested_length=%s preset=%s best_effort=%s timeout_s=%s base_plan=%s',
        scenario_norm,
        requested_length,
        (preset or ''),
        bool(best_effort),
        (total_timeout_s if total_timeout_s is not None else 'none'),
        plan_basename,
    )
    try:
        flow_progress(f"Prepare start: scenario={scenario_norm} length={requested_length}")
    except Exception:
        pass

    try:
        payload = deps._load_preview_payload_from_path(base_plan_path, scenario_norm)
        if not isinstance(payload, dict):
            return {
                'response': (jsonify({'ok': False, 'error': 'Preview plan not embedded in XML. Save XML with Preview first.'}), 404),
            }
        meta, flow_state_for_prepare = deps._canonicalize_payload_flow_from_xml(
            payload,
            xml_path=base_plan_path,
            scenario_label=(scenario_label or scenario_norm),
        )
        preview = payload.get('full_preview') if isinstance(payload, dict) else None
        if not isinstance(preview, dict):
            return {
                'response': (jsonify({'ok': False, 'error': 'Preview plan is missing full_preview.'}), 422),
            }
    except Exception as exc:
        return {
            'response': (jsonify({'ok': False, 'error': f'Failed to load preview plan: {exc}'}), 500),
        }

    return {
        'response': None,
        'j': j,
        'scenario_label': scenario_label,
        'scenario_norm': scenario_norm,
        'preset': preset,
        'mode': mode,
        'best_effort': best_effort,
        'run_generators_request': run_generators_request,
        'cleanup_generated_artifacts': cleanup_generated_artifacts,
        'allow_node_duplicates': allow_node_duplicates,
        'total_timeout_s': total_timeout_s,
        'length': length,
        'requested_length': requested_length,
        'preset_steps': preset_steps,
        'flow_run_remote': flow_run_remote,
        'flow_remote_forced': flow_remote_forced,
        'flow_core_cfg': flow_core_cfg,
        'base_plan_path': base_plan_path,
        'initial_facts_override': initial_facts_override,
        'goal_facts_override': goal_facts_override,
        'started_at': started_at,
        'meta': meta,
        'flow_state_for_prepare': flow_state_for_prepare,
        'preview': preview,
    }


def _prepare_chain_and_assignments(
    deps,
    *,
    backend: Any,
    helpers,
    j: dict[str, Any],
    preview: dict[str, Any],
    flow_state_for_prepare: Any,
    scenario_label: str,
    scenario_norm: str,
    preset: str,
    preset_steps: list[Any],
    mode: str,
    best_effort: bool,
    allow_node_duplicates: bool,
    length: int,
    requested_length: int,
    initial_facts_override: dict[str, list[str]] | None,
    goal_facts_override: dict[str, list[str]] | None,
    base_plan_path: str,
) -> dict[str, Any]:
    warning: str | None = None
    try:
        nodes, _links, adj = deps._build_topology_graph_from_preview_plan(preview)
        stats = deps._flow_compose_docker_stats(nodes)
        eligible_debug = helpers.eligible_debug_summary(nodes, backend=backend)

        chain_ids_in = j.get('chain_ids')
        if (not chain_ids_in) and (not preset_steps):
            try:
                saved_ids = helpers.saved_chain_ids_from_flow_state(flow_state_for_prepare)
                if saved_ids:
                    chain_ids_in = saved_ids
            except Exception:
                pass
        chain_ids: list[str] = []
        if isinstance(chain_ids_in, list) and chain_ids_in:
            for cid in chain_ids_in:
                value = str(cid or '').strip()
                if value:
                    chain_ids.append(value)
            chain_ids = chain_ids[:length]

        explicit_chain = bool(chain_ids)

        if chain_ids:
            repaired_chain = helpers.repair_explicit_chain_nodes(
                chain_ids,
                nodes,
                adj,
                preview=preview,
                preset_steps=preset_steps,
                allow_node_duplicates=allow_node_duplicates,
                length=length,
                requested_length=requested_length,
                best_effort=best_effort,
                mode=mode,
                stats=stats,
                eligible_debug=eligible_debug,
                warning=warning,
                backend=backend,
            )
            if not repaired_chain.get('ok'):
                return {
                    'response': (
                        jsonify(repaired_chain.get('payload') or {'ok': False, 'error': 'Invalid explicit chain.'}),
                        int(repaired_chain.get('status') or 422),
                    ),
                }
            chain_nodes = repaired_chain.get('chain_nodes') or []
            chain_ids = repaired_chain.get('chain_ids') or []
            explicit_chain = bool(repaired_chain.get('explicit_chain'))
            warning = str(repaired_chain.get('warning') or warning or '')
        else:
            chain_nodes = helpers.pick_chain_nodes(
                nodes,
                adj,
                preview=preview,
                preset_steps=preset_steps,
                allow_node_duplicates=allow_node_duplicates,
                length=length,
                backend=backend,
            )
            if len(chain_nodes) < 1:
                return {
                    'response': (
                        jsonify({
                            'ok': False,
                            'error': 'No eligible nodes found in preview plan (vulnerability nodes only for flag-generators).',
                            'available': len(chain_nodes),
                            'stats': stats,
                            'eligible': eligible_debug,
                        }),
                        422,
                    ),
                }
            if (not allow_node_duplicates) and len(chain_nodes) < length:
                return {
                    'response': (
                        jsonify({
                            'ok': False,
                            'error': 'Not enough eligible nodes in preview plan to build the requested chain.',
                            'available': len(chain_nodes),
                            'stats': stats,
                            'eligible': eligible_debug,
                        }),
                        422,
                    ),
                }
            chain_ids = [str(node.get('id') or '').strip() for node in chain_nodes if str(node.get('id') or '').strip()]
    except Exception as exc:
        current_app.logger.exception('[flow.prepare_preview_for_execute] internal error: %s', exc)
        return {
            'response': (
                jsonify({
                    'ok': False,
                    'error': f'Internal error preparing preview for execution: {exc}',
                    'base_preview_plan_path': base_plan_path,
                }),
                500,
            ),
        }

    try:
        length = len(chain_nodes)
    except Exception:
        pass

    flag_assignments = helpers.reuse_saved_flag_assignments(
        flow_state_for_prepare,
        chain_nodes,
        scenario_label=(scenario_label or scenario_norm),
        scenario_norm=scenario_norm,
        backend=backend,
    )

    if not flag_assignments:
        if preset_steps:
            preset_assignments, preset_err = deps._flow_compute_flag_assignments_for_preset(preview, chain_nodes, scenario_label or scenario_norm, preset)
            if preset_err:
                return {
                    'response': (jsonify({'ok': False, 'error': f'Error: {preset_err}', 'stats': stats}), 422),
                }
            flag_assignments = preset_assignments
        else:
            flag_assignments = deps._flow_compute_flag_assignments(
                preview,
                chain_nodes,
                scenario_label or scenario_norm,
                initial_facts_override=initial_facts_override,
                goal_facts_override=goal_facts_override,
            )

    try:
        hint_refresh_triggers = {'preview', 'resolve', 'resolve_hints', 'hint', 'hint_only'}
        should_force_refresh_hints = bool(mode in hint_refresh_triggers)
    except Exception:
        should_force_refresh_hints = False

    if should_force_refresh_hints:
        try:
            flag_assignments = helpers.refresh_hints_for_current_chain(
                flag_assignments,
                chain_nodes=chain_nodes,
                gen_by_id={},
                scenario_label=(scenario_label or scenario_norm),
                scenario_norm=scenario_norm,
                backend=backend,
            )
        except Exception:
            pass

    try:
        node_ids = [str(node.get('id') or '').strip() for node in (chain_nodes or []) if isinstance(node, dict) and str(node.get('id') or '').strip()]
        has_dupes = len(set(node_ids)) != len(node_ids)
    except Exception:
        has_dupes = False

    if (not explicit_chain) and (not preset_steps) and (not has_dupes):
        debug_dag = bool(j.get('debug_dag'))
        chain_nodes, flag_assignments, dag_debug = deps._flow_reorder_chain_by_generator_dag(
            chain_nodes,
            flag_assignments,
            scenario_label=(scenario_label or scenario_norm),
            return_debug=bool(debug_dag),
        )
        try:
            chain_ids = [str(node.get('id') or '').strip() for node in chain_nodes if isinstance(node, dict) and str(node.get('id') or '').strip()]
        except Exception:
            pass
    else:
        debug_dag = bool(j.get('debug_dag'))
        dag_debug = None

    has_assignment_ids = False
    try:
        has_assignment_ids = any(
            isinstance(assignment, dict) and str(assignment.get('id') or assignment.get('generator_id') or '').strip()
            for assignment in (flag_assignments or [])
        )
    except Exception:
        has_assignment_ids = False

    if (not flag_assignments) or (not has_assignment_ids):
        flow_valid = False
        flow_errors = ['missing flag assignments']
        try:
            gens_enabled, _ = deps._flag_generators_from_enabled_sources()
        except Exception:
            gens_enabled = []
        try:
            node_gens_enabled, _ = deps._flag_node_generators_from_enabled_sources()
        except Exception:
            node_gens_enabled = []
        try:
            eligible_flag_gens = len([gen for gen in (gens_enabled or []) if isinstance(gen, dict)])
        except Exception:
            eligible_flag_gens = 0
        try:
            eligible_node_gens = len([gen for gen in (node_gens_enabled or []) if isinstance(gen, dict)])
        except Exception:
            eligible_node_gens = 0
        try:
            vuln_nodes = len([node for node in (chain_nodes or []) if isinstance(node, dict) and deps._flow_node_is_vuln(node)])
        except Exception:
            vuln_nodes = 0
        try:
            docker_nodes = len([node for node in (chain_nodes or []) if isinstance(node, dict) and deps._flow_node_is_docker_role(node)])
        except Exception:
            docker_nodes = 0
        flow_errors.extend([
            f'eligible_flag_generators={eligible_flag_gens}',
            f'eligible_flag_node_generators={eligible_node_gens}',
            f'chain_nodes={len(chain_nodes or [])}',
            f'chain_vuln_nodes={vuln_nodes}',
            f'chain_docker_nodes={docker_nodes}',
        ])
    else:
        flow_valid, flow_errors = deps._flow_validate_chain_order_by_requires_produces(
            chain_nodes,
            flag_assignments,
            scenario_label=(scenario_label or scenario_norm),
        )
    try:
        assign_ids = [str(assignment.get('id') or assignment.get('generator_id') or '').strip() for assignment in (flag_assignments or []) if isinstance(assignment, dict)]
        chain_ids_dbg = [str(node.get('id') or '').strip() for node in (chain_nodes or []) if isinstance(node, dict) and str(node.get('id') or '').strip()]
        flow_errors_detail = (
            f'assignments={len(flag_assignments or [])} '
            f'assignments_with_id={len([value for value in assign_ids if value])} '
            f'chain_nodes={len(chain_nodes or [])} '
            f'chain_ids={",".join(chain_ids_dbg)}'
        )
    except Exception:
        flow_errors_detail = None
    flags_enabled = bool(flow_valid)
    run_generators = bool(flags_enabled or j.get('mode') in {'resolve', 'resolve_hints', 'hint', 'hint_only'})
    try:
        if not flow_valid:
            current_app.logger.warning(
                '[flow.prepare_preview_for_execute] invalid flow: %s',
                (flow_errors_detail or (flow_errors or [])),
            )
    except Exception:
        pass

    return {
        'response': None,
        'stats': stats,
        'warning': warning,
        'length': length,
        'chain_nodes': chain_nodes,
        'chain_ids': chain_ids,
        'flag_assignments': flag_assignments,
        'debug_dag': debug_dag,
        'dag_debug': dag_debug,
        'flow_valid': flow_valid,
        'flow_errors': flow_errors,
        'flow_errors_detail': flow_errors_detail,
        'flags_enabled': flags_enabled,
        'run_generators': run_generators,
    }


def _prepare_generator_runtime_state(
    deps,
    *,
    backend: Any,
    helpers,
    preview: dict[str, Any],
    chain_ids: list[str],
    chain_nodes: list[dict[str, Any]],
    flag_assignments: list[dict[str, Any]],
    flags_enabled: bool,
    run_generators: bool,
    scenario_label: str,
    scenario_norm: str,
    base_plan_path: str,
) -> dict[str, Any]:
    if run_generators:
        try:
            hosts = preview.get('hosts') or []
            if isinstance(hosts, list):
                for host in hosts:
                    if not isinstance(host, dict):
                        continue
                    host_id = str(host.get('node_id') or '').strip()
                    if host_id and host_id in chain_ids:
                        host['role'] = 'Docker'
        except Exception:
            pass

    try:
        gens_for_cfg, _ = deps._flag_generators_from_enabled_sources()
    except Exception:
        gens_for_cfg = []
    try:
        node_gens_for_cfg, _ = deps._flag_node_generators_from_enabled_sources()
    except Exception:
        node_gens_for_cfg = []

    try:
        gen_by_id = helpers.build_generator_index(gens_for_cfg, node_gens_for_cfg)
    except Exception:
        gen_by_id = {}

    if run_generators:
        try:
            flag_assignments = helpers.clear_prior_outputs_from_assignments(
                flag_assignments,
                gen_by_id=gen_by_id,
            )
        except Exception:
            pass

    if flags_enabled:
        missing_or_disabled = helpers.find_missing_or_disabled_generators(
            flag_assignments,
            chain_nodes,
            gen_by_id=gen_by_id,
            backend=backend,
        )

        if missing_or_disabled:
            bad = missing_or_disabled[0]
            msg = f"Generator {bad.get('generator_id')} ({bad.get('type')}) is {bad.get('reason')}."
            try:
                node_id = str(bad.get('node_id') or '').strip()
                if node_id:
                    msg += f" Node: {node_id}"
                node_name = str(bad.get('node_name') or '').strip()
                if node_name:
                    msg += f" ({node_name})"
            except Exception:
                pass
            return {
                'response': (
                    jsonify({
                        'ok': False,
                        'error': msg,
                        'details': missing_or_disabled,
                        'scenario': scenario_label or scenario_norm,
                        'length': len(chain_nodes or []),
                        'chain': [
                            {
                                'id': str(node.get('id') or ''),
                                'name': str(node.get('name') or ''),
                                'type': str(node.get('type') or ''),
                            }
                            for node in (chain_nodes or [])
                            if isinstance(node, dict)
                        ],
                        'flag_assignments': flag_assignments,
                    }),
                    422,
                ),
            }

    candidate_paths: list[str] = []
    if base_plan_path:
        candidate_paths.append(str(base_plan_path))
    flag_seed_epoch = helpers.determine_flag_seed_epoch(candidate_paths, time_module=time)
    host_by_id = helpers.build_host_index(preview)

    return {
        'response': None,
        'flag_assignments': flag_assignments,
        'gen_by_id': gen_by_id,
        'flag_seed_epoch': flag_seed_epoch,
        'host_by_id': host_by_id,
    }


def _execute_or_prepare_assignments(
    deps,
    *,
    helpers,
    preview: dict[str, Any],
    host_by_id: dict[str, dict[str, Any]],
    gen_by_id: dict[str, dict[str, Any]],
    flag_assignments: list[dict[str, Any]],
    run_generators: bool,
    flow_run_remote: bool,
    flow_core_cfg: dict[str, Any] | None,
    flow_remote_repo_dir: str | None,
    started_at: float,
    total_timeout_s: int | None,
    best_effort: bool,
    length: int,
    stats: dict[str, Any],
    chain_nodes: list[dict[str, Any]],
    base_plan_path: str,
    scenario_label: str,
    scenario_norm: str,
    backend: Any,
    flow_default_generator_config,
    flow_try_run_generator,
    flow_try_run_generator_remote,
    preview_host_ip4,
    redact_kv_for_ui,
    flow_stage_file_inputs_for_generator,
) -> dict[str, Any]:
    created_run_dirs: list[str] = []
    failed_run_dirs: list[str] = []
    progress_log: list[str] = []
    generation_failures: list[dict[str, Any]] = []
    generation_skipped: list[dict[str, Any]] = []
    generator_runs: list[dict[str, Any]] = []

    if run_generators:
        try:
            flow_context: dict[str, Any] = {}
            artifact_context: dict[str, str] = {}

            apply_outputs_to_hint_text = helpers.apply_outputs_to_hint_text
            apply_node_placeholders = helpers.apply_node_placeholders

            def flow_progress(msg: str) -> None:
                try:
                    progress_log.append(str(msg))
                except Exception:
                    pass
                try:
                    current_app.logger.info('[flow.progress] %s', msg)
                except Exception:
                    pass

            seen_flag_values: set[str] = set()
            deadline = (started_at + float(total_timeout_s)) if total_timeout_s is not None else None
            occurrence_ctr: dict[tuple[str, str], int] = {}
            total_assignments = len([item for item in (flag_assignments or []) if isinstance(item, dict)])
            run_index = 0
            cleaned_scenario_roots: set[str] = set()
            for fa in (flag_assignments or []):
                if not isinstance(fa, dict):
                    continue
                cid = str(fa.get('node_id') or '').strip()
                host = host_by_id.get(cid)
                if not host or not isinstance(host, dict):
                    continue
                preview_ip4 = preview_host_ip4(host)

                meta_h = host.get('metadata')
                if not isinstance(meta_h, dict):
                    meta_h = {}
                    host['metadata'] = meta_h

                generator_id = str(fa.get('id') or '').strip()
                assignment_type = str(fa.get('type') or '').strip() or 'flag-generator'
                generator_catalog = str(fa.get('generator_catalog') or '').strip() or 'flag_generators'
                seed_val = preview.get('seed') if isinstance(preview, dict) else None

                occ_key = (cid, generator_id)
                occ = int(occurrence_ctr.get(occ_key, 0) or 0)
                occurrence_ctr[occ_key] = occ + 1

                cfg_full, cfg, inputs_mismatch, gen_def = helpers.build_generator_run_config(
                    fa,
                    host,
                    preview=preview,
                    preview_ip4=preview_ip4,
                    flow_context=flow_context,
                    gen_by_id=gen_by_id,
                    flow_default_generator_config=lambda assignment: flow_default_generator_config(
                        assignment,
                        seed_val=seed_val,
                        occurrence_idx=occ,
                    ),
                    backend=backend,
                    time_module=time,
                )

                flow_out_dir = ''
                ok_run = False
                note = ''
                manifest_path = None
                actual_output_keys: list[str] = []
                outs = None
                declared_output_keys = helpers.prepare_assignment_for_run(
                    fa,
                    cfg=cfg,
                    cfg_full=cfg_full,
                    redact_kv_for_ui=redact_kv_for_ui,
                )
                mismatch: dict[str, Any] = {}

                try:
                    run_index += 1
                except Exception:
                    run_index = run_index
                try:
                    if generator_id:
                        if deadline is not None and time.monotonic() >= deadline:
                            generation_skipped.append({
                                'node_id': cid,
                                'node_name': str(host.get('name') or ''),
                                'generator_id': generator_id,
                                'reason': 'time budget exceeded',
                            })
                            break

                        try:
                            flow_progress(
                                f"Running generator {run_index}/{total_assignments}: {generator_id} @ {str(host.get('name') or '')}"
                            )
                        except Exception:
                            pass

                        flow_run_id = deps._local_timestamp_safe() + '-' + uuid.uuid4().hex[:10]
                        flow_out_dir = helpers.prepare_generator_run_dir(
                            generator_id,
                            assignment_type,
                            scenario_norm,
                            host_name=str(host.get('name') or ''),
                            node_id=cid,
                            run_index=run_index,
                            flow_run_remote=flow_run_remote,
                            cleaned_scenario_roots=cleaned_scenario_roots,
                        )

                        print(f"DEBUG: flow_run_remote={flow_run_remote} flow_out_dir={flow_out_dir}", flush=True)
                        try:
                            created_run_dirs.append(str(flow_out_dir))
                        except Exception:
                            pass

                        if not flow_run_remote:
                            try:
                                gen_def = gen_by_id.get(generator_id)
                                if isinstance(gen_def, dict) and isinstance(cfg, dict):
                                    flow_stage_file_inputs_for_generator(cfg, gen_def, run_dir=str(flow_out_dir), run_index=run_index)
                            except Exception:
                                pass

                        remaining = None
                        if deadline is not None:
                            try:
                                remaining = int(max(1.0, deadline - time.monotonic()))
                            except Exception:
                                remaining = 1
                        gen_timeout_s = 120
                        if remaining is not None:
                            gen_timeout_s = min(gen_timeout_s, remaining)
                        effective_injects = helpers.resolve_and_stage_inject_files(
                            fa,
                            artifact_context=artifact_context,
                            flow_context=flow_context,
                            created_run_dirs=created_run_dirs,
                            flow_out_dir=str(flow_out_dir),
                            flow_run_remote=flow_run_remote,
                            run_index=run_index,
                            backend=backend,
                        )

                        run_result = helpers.invoke_generator_run(
                            generator_id,
                            flow_run_remote=flow_run_remote,
                            flow_remote_repo_dir=flow_remote_repo_dir,
                            flow_core_cfg=flow_core_cfg if isinstance(flow_core_cfg, dict) else None,
                            flow_out_dir=str(flow_out_dir or ''),
                            cfg=cfg,
                            assignment_type=assignment_type,
                            gen_timeout_s=gen_timeout_s,
                            effective_injects=effective_injects,
                            flow_try_run_generator_remote=flow_try_run_generator_remote,
                            flow_try_run_generator=flow_try_run_generator,
                        )
                        ok_run = bool(run_result.get('ok_run'))
                        note = str(run_result.get('note') or '')
                        manifest_path = str(run_result.get('manifest_path') or '') or None
                        manifest_outputs = run_result.get('manifest_outputs') if isinstance(run_result.get('manifest_outputs'), dict) else None
                        run_stdout = run_result.get('run_stdout') if isinstance(run_result.get('run_stdout'), str) else None
                        run_stderr = run_result.get('run_stderr') if isinstance(run_result.get('run_stderr'), str) else None

                        try:
                            current_app.logger.info(
                                '[flow.generator] node=%s generator=%s ok=%s note=%s manifest=%s out_dir=%s',
                                cid,
                                generator_id,
                                bool(ok_run),
                                str(note or ''),
                                str(manifest_path or ''),
                                str(flow_out_dir or ''),
                            )
                        except Exception:
                            pass

                        if not ok_run:
                            try:
                                current_app.logger.error(
                                    '[flow.generator.debug] node=%s generator=%s type=%s note=%s out_dir=%s manifest=%s stdout_tail=%s stderr_tail=%s',
                                    cid,
                                    generator_id,
                                    assignment_type,
                                    str(note or ''),
                                    str(flow_out_dir or ''),
                                    str(manifest_path or ''),
                                    (run_stdout or '').strip()[-4000:] if isinstance(run_stdout, str) else '',
                                    (run_stderr or '').strip()[-4000:] if isinstance(run_stderr, str) else '',
                                )
                            except Exception:
                                pass

                        log_path = helpers.write_generator_run_log(
                            outputs_dir_getter=deps._outputs_dir,
                            generator_id=generator_id,
                            node_name=str(host.get('name') or cid or 'node'),
                            flow_run_id=str(flow_run_id or uuid.uuid4().hex),
                            ok_run=ok_run,
                            note=str(note or ''),
                            run_stdout=run_stdout,
                            run_stderr=run_stderr,
                        )

                        if not ok_run and log_path:
                            try:
                                current_app.logger.error('[flow.generator.debug] detailed log written to %s', str(log_path))
                            except Exception:
                                pass

                        try:
                            generator_runs.append({
                                'node_id': cid,
                                'node_name': str(host.get('name') or ''),
                                'generator_id': generator_id,
                                'type': assignment_type,
                                'ok': bool(ok_run),
                                'note': str(note or ''),
                                'out_dir': str(flow_out_dir or ''),
                                'manifest': str(manifest_path or ''),
                                'stdout': (run_stdout or '')[-4000:] if isinstance(run_stdout, str) else '',
                                'stderr': (run_stderr or '')[-4000:] if isinstance(run_stderr, str) else '',
                                'log_path': str(log_path or ''),
                            })
                        except Exception:
                            pass

                        try:
                            flow_progress(
                                f"Completed generator {run_index}/{total_assignments}: {generator_id} -> {'ok' if ok_run else 'failed'}"
                            )
                        except Exception:
                            pass

                        if ok_run and (not manifest_path) and declared_output_keys and not manifest_outputs:
                            ok_run = False
                            note = f'outputs.json missing for generator={generator_id}'

                        if not ok_run:
                            generation_failures.append({
                                'node_id': cid,
                                'node_name': str(host.get('name') or ''),
                                'generator_id': generator_id,
                                'error': str(note or 'generator execution failed'),
                                'run_dir': str(flow_out_dir or ''),
                            })
                            try:
                                if flow_out_dir:
                                    failed_run_dirs.append(str(flow_out_dir))
                            except Exception:
                                pass

                            if not best_effort:
                                break

                        if ok_run and (manifest_outputs is not None or (manifest_path and os.path.exists(manifest_path))):
                            try:
                                if isinstance(manifest_outputs, dict):
                                    outs = manifest_outputs
                                elif manifest_path and os.path.exists(manifest_path):
                                    with open(manifest_path, 'r', encoding='utf-8') as fh:
                                        manifest_doc = json.load(fh) or {}
                                    outs = manifest_doc.get('outputs') if isinstance(manifest_doc, dict) else None
                                if isinstance(outs, dict):
                                    processed_outputs = helpers.process_generator_outputs(
                                        fa,
                                        outs,
                                        ok_run=ok_run,
                                        note=note,
                                        manifest_path=str(manifest_path or ''),
                                        flow_out_dir=str(flow_out_dir or ''),
                                        assignment_type=assignment_type,
                                        gen_def=gen_def,
                                        preview_ip4=preview_ip4,
                                        node_id=cid,
                                        generator_id=generator_id,
                                        flow_context=flow_context,
                                        seen_flag_values=seen_flag_values,
                                        redact_kv_for_ui=redact_kv_for_ui,
                                        apply_outputs_to_hint_text=apply_outputs_to_hint_text,
                                        apply_node_placeholders=apply_node_placeholders,
                                        backend=backend,
                                    )
                                    ok_run = bool(processed_outputs.get('ok_run'))
                                    note = str(processed_outputs.get('note') or '')
                                    outs = processed_outputs.get('outs') if isinstance(processed_outputs.get('outs'), dict) else outs
                                    actual_output_keys = list(processed_outputs.get('actual_output_keys') or [])
                            except RuntimeError:
                                raise
                            except Exception:
                                actual_output_keys = []

                        helpers.capture_artifact_context(artifact_context, outs, str(flow_out_dir or ''))
                        helpers.materialize_hint_file(
                            fa,
                            flow_out_dir=str(flow_out_dir or ''),
                            flow_run_remote=flow_run_remote,
                            flow_core_cfg=flow_core_cfg if isinstance(flow_core_cfg, dict) else None,
                            backend=backend,
                        )
                        mismatch = helpers.compute_output_mismatch(
                            declared_output_keys,
                            actual_output_keys,
                            ok_run=ok_run,
                        )
                except Exception as exc:
                    if 'duplicate flag value' in str(exc):
                        raise
                    ok_run, note, manifest_path = False, f'generator exception: {exc}', None
                    if generator_id:
                        generation_failures.append({
                            'node_id': cid,
                            'node_name': str(host.get('name') or ''),
                            'generator_id': generator_id,
                            'error': str(note or ''),
                            'run_dir': str(flow_out_dir or ''),
                        })

                finalized_assignment = helpers.finalize_generator_assignment_metadata(
                    fa,
                    meta_h,
                    flow_out_dir=str(flow_out_dir or ''),
                    flow_run_remote=flow_run_remote,
                    generator_catalog=generator_catalog,
                    generator_id=generator_id,
                    assignment_type=assignment_type,
                    cfg=cfg,
                    declared_output_keys=declared_output_keys,
                    actual_output_keys=actual_output_keys,
                    mismatch=mismatch,
                    inputs_mismatch=inputs_mismatch,
                    manifest_path=str(manifest_path or ''),
                    ok_run=ok_run,
                    note=str(note or ''),
                    backend=backend,
                )
                ok_run = bool(finalized_assignment.get('ok_run'))
                note = str(finalized_assignment.get('note') or '')

            try:
                realized_flags: list[str] = []
                for assignment in (flag_assignments or []):
                    if not isinstance(assignment, dict):
                        continue
                    resolved_outputs = assignment.get('resolved_outputs') if isinstance(assignment.get('resolved_outputs'), dict) else {}
                    flag_val = None
                    if isinstance(resolved_outputs, dict):
                        flag_val = resolved_outputs.get('Flag(flag_id)') or resolved_outputs.get('flag')
                    if not flag_val:
                        flag_val = assignment.get('flag_value')
                    if not flag_val:
                        try:
                            manifest_path = str(assignment.get('outputs_manifest') or '').strip()
                            if (not flow_run_remote) and manifest_path and os.path.exists(manifest_path):
                                with open(manifest_path, 'r', encoding='utf-8') as mf:
                                    manifest_doc = json.load(mf) or {}
                                outputs = manifest_doc.get('outputs') if isinstance(manifest_doc, dict) else None
                                if isinstance(outputs, dict):
                                    flag_val = outputs.get('Flag(flag_id)') or outputs.get('flag')
                        except Exception:
                            flag_val = None
                    if isinstance(flag_val, str) and flag_val.strip():
                        realized_flags.append(flag_val.strip())
                if realized_flags and len(set(realized_flags)) != len(realized_flags):
                    raise RuntimeError('duplicate flag value detected after resolve')
            except RuntimeError:
                raise
            except Exception:
                pass

            if generation_failures:
                failure_result = helpers.handle_generation_failures(
                    generation_failures,
                    created_run_dirs=created_run_dirs or [],
                    failed_run_dirs=failed_run_dirs or [],
                    best_effort=bool(best_effort),
                )
                if failure_result.get('should_fail'):
                    return {
                        'response': (
                            jsonify({
                                'ok': False,
                                'error': f'{len(generation_failures)} generator run(s) failed; cannot prepare preview for execute.',
                                'scenario': scenario_label or scenario_norm,
                                'length': length,
                                'stats': stats,
                                'chain': [{'id': str(node.get('id') or ''), 'name': str(node.get('name') or ''), 'type': str(node.get('type') or '')} for node in chain_nodes],
                                'flag_assignments': flag_assignments,
                                'generation_failures': generation_failures,
                                'generation_skipped': generation_skipped,
                                'base_preview_plan_path': base_plan_path,
                                'best_effort': bool(best_effort),
                            }),
                            422,
                        ),
                    }
        except Exception:
            pass
    else:
        try:
            occurrence_ctr: dict[tuple[str, str], int] = {}
            for fa in (flag_assignments or []):
                if not isinstance(fa, dict):
                    continue
                cid = str(fa.get('node_id') or '').strip()
                host = host_by_id.get(cid)
                preview_ip4 = preview_host_ip4(host) if isinstance(host, dict) else ''

                generator_id = str(fa.get('id') or '').strip()
                seed_val = preview.get('seed') if isinstance(preview, dict) else None

                occ_key = (cid, generator_id)
                occ = int(occurrence_ctr.get(occ_key, 0) or 0)
                occurrence_ctr[occ_key] = occ + 1

                helpers.prepare_disabled_assignment_view(
                    fa,
                    host if isinstance(host, dict) else None,
                    preview=preview,
                    preview_ip4=preview_ip4,
                    occurrence_idx=occ,
                    gen_by_id=gen_by_id,
                    flow_default_generator_config=flow_default_generator_config,
                    redact_kv_for_ui=redact_kv_for_ui,
                    backend=backend,
                    time_module=time,
                )
        except Exception:
            pass

    try:
        helpers.normalize_postrun_inject_files(flag_assignments, created_run_dirs or [])
    except Exception:
        pass

    return {
        'response': None,
        'flag_assignments': flag_assignments,
        'created_run_dirs': created_run_dirs,
        'failed_run_dirs': failed_run_dirs,
        'progress_log': progress_log,
        'generation_failures': generation_failures,
        'generation_skipped': generation_skipped,
        'generator_runs': generator_runs,
    }


def _finalize_prepare_preview_response(
    deps,
    *,
    helpers,
    flag_assignments: list[dict[str, Any]],
    run_generators_request: bool,
    mode: str,
    base_plan_path: str,
    scenario_label: str,
    scenario_norm: str,
    length: int,
    requested_length: int,
    chain_nodes: list[dict[str, Any]],
    flags_enabled: bool,
    flow_valid: bool,
    flow_errors: list[str],
    meta: Any,
    preview: dict[str, Any],
    host_by_id: dict[str, dict[str, Any]],
    preview_host_ip4,
    created_run_dirs: list[str],
    failed_run_dirs: list[str],
    cleanup_generated_artifacts: Any,
    stats: dict[str, Any],
    best_effort: bool,
    started_at: float,
    generator_runs: list[dict[str, Any]],
    progress_log: list[str],
    generation_failures: list[dict[str, Any]],
    generation_skipped: list[dict[str, Any]],
    debug_dag: bool,
    dag_debug: Any,
    warning: str | None,
    backend: Any,
    flow_errors_detail: Any,
) -> tuple[Any, int]:
    try:
        try:
            normalized_flow_state = deps._enrich_flow_state_with_artifacts({'flag_assignments': flag_assignments})
            normalized_assignments = normalized_flow_state.get('flag_assignments') if isinstance(normalized_flow_state, dict) else None
            if isinstance(normalized_assignments, list):
                flag_assignments = normalized_assignments
        except Exception:
            pass

        persisted_flag_assignments = deps._flow_strip_runtime_sensitive_fields(flag_assignments)
        try:
            if run_generators_request or mode in {'resolve', 'resolve_hints', 'hint', 'hint_only'}:
                persisted_flag_assignments = [
                    deps._canonicalize_flow_assignment_paths(item) if isinstance(item, dict) else item
                    for item in (flag_assignments or [])
                ]
        except Exception:
            persisted_flag_assignments = persisted_flag_assignments
        flow_meta = {
            'source_preview_plan_path': deps._abs_path_or_original(base_plan_path),
            'scenario': scenario_label or scenario_norm,
            'length': length,
            'requested_length': requested_length,
            'chain': [{'id': str(node.get('id') or ''), 'name': str(node.get('name') or ''), 'type': str(node.get('type') or '')} for node in chain_nodes],
            'flag_assignments': persisted_flag_assignments,
            'flags_enabled': bool(flags_enabled),
            'flow_valid': bool(flow_valid),
            'flow_errors': list(flow_errors or []),
            'modified_at': deps._iso_now(),
        }
        try:
            flow_existing = meta.get('flow') if isinstance(meta, dict) else None
            if isinstance(flow_existing, dict):
                init_facts = deps._flow_normalize_fact_override(flow_existing.get('initial_facts'))
                goal_facts = deps._flow_normalize_fact_override(flow_existing.get('goal_facts'))
                if init_facts:
                    flow_meta['initial_facts'] = init_facts
                if goal_facts:
                    flow_meta['goal_facts'] = goal_facts
        except Exception:
            pass
    except Exception:
        flow_meta = {
            'source_preview_plan_path': deps._abs_path_or_original(base_plan_path),
            'scenario': scenario_label or scenario_norm,
            'length': length,
            'requested_length': requested_length,
            'chain': [{'id': str(node.get('id') or ''), 'name': str(node.get('name') or ''), 'type': str(node.get('type') or '')} for node in chain_nodes],
            'flag_assignments': flag_assignments,
            'flags_enabled': bool(flags_enabled),
            'flow_valid': bool(flow_valid),
            'flow_errors': list(flow_errors or []),
            'modified_at': deps._iso_now(),
        }

    persist_result = helpers.persist_prepare_preview_plan(
        meta=meta if isinstance(meta, dict) else None,
        preview=preview,
        flow_meta=flow_meta,
        base_plan_path=base_plan_path,
        scenario_label=(scenario_label or scenario_norm),
        scenario_norm=scenario_norm,
        backend=backend,
    )
    if not persist_result.get('ok'):
        return jsonify({'ok': False, 'error': str(persist_result.get('error') or 'Failed to persist flow-modified preview plan.')}), 500
    out_path = str(persist_result.get('out_path') or '')
    meta = persist_result.get('meta') if isinstance(persist_result.get('meta'), dict) else meta

    try:
        current_app.logger.info(
            '[flow.prepare_preview_for_execute] done scenario=%s chain_len=%s flow_valid=%s flow_errors=%s detail=%s',
            scenario_norm,
            len(chain_nodes or []),
            bool(flow_valid),
            (flow_errors or []),
            (flow_errors_detail or ''),
        )
    except Exception:
        pass

    host_ip_map = helpers.build_host_ip_map(host_by_id or {}, preview_host_ip4=preview_host_ip4)

    flag_assignments_out = flag_assignments
    try:
        flag_assignments_out = [
            deps._canonicalize_flow_assignment_paths(item) if isinstance(item, dict) else item
            for item in (flag_assignments or [])
        ]
    except Exception:
        flag_assignments_out = flag_assignments

    try:
        realized_flags = helpers.collect_realized_flags(flag_assignments or [])
        if realized_flags and len(set(realized_flags)) != len(realized_flags):
            return jsonify({
                'ok': False,
                'error': 'Duplicate flag value detected during resolve; retry with a different chain.',
                'scenario': scenario_label or scenario_norm,
                'length': length,
                'chain': [{'id': str(node.get('id') or ''), 'name': str(node.get('name') or ''), 'type': str(node.get('type') or '')} for node in chain_nodes],
                'flag_assignments': flag_assignments_out,
            }), 422
    except Exception:
        pass

    cleanup_deleted_run_dirs = helpers.cleanup_generated_run_dirs(
        cleanup_generated_artifacts=bool(cleanup_generated_artifacts),
        created_run_dirs=created_run_dirs or [],
        failed_run_dirs=failed_run_dirs or [],
    )

    success_payload = helpers.build_prepare_preview_success_payload(
        scenario_label=scenario_label,
        scenario_norm=scenario_norm,
        length=length,
        requested_length=requested_length,
        stats=stats,
        chain_nodes=chain_nodes,
        flag_assignments_out=flag_assignments_out,
        flags_enabled=bool(flags_enabled),
        flow_valid=bool(flow_valid),
        flow_errors=list(flow_errors or []),
        flow_errors_detail=flow_errors_detail,
        host_ip_map=host_ip_map,
        meta=meta if isinstance(meta, dict) else None,
        base_plan_path=base_plan_path,
        out_path=out_path,
        best_effort=bool(best_effort),
        elapsed_s=float(time.monotonic() - started_at),
        generator_runs=generator_runs,
        progress_log=progress_log,
        generation_failures=generation_failures,
        generation_skipped=generation_skipped,
        created_run_dirs=created_run_dirs,
        failed_run_dirs=failed_run_dirs,
        cleanup_generated_artifacts=bool(cleanup_generated_artifacts),
        cleanup_deleted_run_dirs=cleanup_deleted_run_dirs,
        debug_dag=bool(debug_dag),
        dag_debug=dag_debug,
        warning=warning,
        backend=backend,
    )
    return jsonify(success_payload), (422 if generation_failures and not best_effort else 200)


def _build_runtime_adapters(*, helpers, backend: Any, scenario_norm: str, flag_seed_epoch: Any) -> dict[str, Any]:
    def _flow_default_generator_config(assignment: dict[str, Any], *, seed_val: Any, occurrence_idx: int = 0) -> dict[str, Any]:
        return helpers.flow_default_generator_config(
            assignment,
            seed_val=seed_val,
            occurrence_idx=occurrence_idx,
            flag_seed_epoch=flag_seed_epoch,
            scenario_norm=scenario_norm,
            backend=backend,
        )

    def _flow_try_run_generator(
        generator_id: str,
        *,
        out_dir: str,
        config: dict[str, Any],
        kind: str = 'flag-generator',
        timeout_s: int = 120,
        inject_files_override: list[str] | None = None,
    ) -> tuple[bool, str, str | None, str | None, str | None]:
        return helpers.flow_try_run_generator(
            generator_id,
            out_dir=out_dir,
            config=config,
            kind=kind,
            timeout_s=timeout_s,
            inject_files_override=inject_files_override,
            backend=backend,
        )

    def _flow_try_run_generator_remote(
        generator_id: str,
        *,
        out_dir: str,
        config: dict[str, Any],
        kind: str = 'flag-generator',
        timeout_s: int = 120,
        inject_files_override: list[str] | None = None,
        core_cfg: dict[str, Any],
        repo_dir: str,
    ) -> tuple[bool, str, str | None, dict[str, Any] | None, str | None, str | None]:
        return helpers.flow_try_run_generator_remote(
            generator_id,
            out_dir=out_dir,
            config=config,
            kind=kind,
            timeout_s=timeout_s,
            inject_files_override=inject_files_override,
            core_cfg=core_cfg,
            repo_dir=repo_dir,
            backend=backend,
        )

    def _preview_host_ip4(host: dict) -> str:
        return helpers.preview_host_ip4(host, backend=backend)

    def _flow_stage_file_inputs_for_generator(cfg_to_pass: dict[str, Any], gen_def: dict[str, Any], *, run_dir: str, run_index: int = None) -> None:
        helpers.flow_stage_file_inputs_for_generator(
            cfg_to_pass,
            gen_def,
            run_dir=run_dir,
            run_index=run_index,
            backend=backend,
        )

    return {
        'redact_kv_for_ui': helpers.redact_kv_for_ui,
        'flow_default_generator_config': _flow_default_generator_config,
        'flow_try_run_generator': _flow_try_run_generator,
        'flow_try_run_generator_remote': _flow_try_run_generator_remote,
        'preview_host_ip4': _preview_host_ip4,
        'flow_stage_file_inputs_for_generator': _flow_stage_file_inputs_for_generator,
    }


def execute_impl(*, backend: Any):
    deps = _backend_dependencies(backend)

    # Stub for early progress calls; overridden later if generator runs occur.
    def _flow_progress(msg: str) -> None:
        try:
            current_app.logger.info('[flow.progress] %s', msg)
        except Exception:
            pass

    from webapp import flow_prepare_preview_helpers as _flow_prepare_preview_helpers

    request_context = _load_prepare_preview_request_context(deps=deps, flow_progress=_flow_progress)
    response = request_context.get('response')
    if response is not None:
        return response

    j = request_context['j']
    scenario_label = str(request_context['scenario_label'])
    scenario_norm = str(request_context['scenario_norm'])
    preset = str(request_context['preset'])
    mode = str(request_context['mode'])
    best_effort = bool(request_context['best_effort'])
    run_generators_request = bool(request_context['run_generators_request'])
    cleanup_generated_artifacts = request_context['cleanup_generated_artifacts']
    allow_node_duplicates = bool(request_context['allow_node_duplicates'])
    total_timeout_s = request_context['total_timeout_s']
    length = int(request_context['length'])
    requested_length = int(request_context['requested_length'])
    preset_steps = request_context['preset_steps'] or []
    flow_run_remote = bool(request_context['flow_run_remote'])
    flow_remote_forced = bool(request_context['flow_remote_forced'])
    flow_core_cfg = request_context['flow_core_cfg'] if isinstance(request_context['flow_core_cfg'], dict) else None
    base_plan_path = str(request_context['base_plan_path'] or '')
    initial_facts_override = request_context['initial_facts_override']
    goal_facts_override = request_context['goal_facts_override']
    started_at = float(request_context['started_at'])
    meta = request_context['meta'] if isinstance(request_context['meta'], dict) else request_context['meta']
    flow_state_for_prepare = request_context['flow_state_for_prepare']
    preview = request_context['preview']

    prepared_chain = _prepare_chain_and_assignments(
        deps=deps,
        backend=backend,
        helpers=_flow_prepare_preview_helpers,
        j=j,
        preview=preview,
        flow_state_for_prepare=flow_state_for_prepare,
        scenario_label=scenario_label,
        scenario_norm=scenario_norm,
        preset=preset,
        preset_steps=preset_steps,
        mode=mode,
        best_effort=best_effort,
        allow_node_duplicates=allow_node_duplicates,
        length=length,
        requested_length=requested_length,
        initial_facts_override=initial_facts_override,
        goal_facts_override=goal_facts_override,
        base_plan_path=base_plan_path,
    )
    response = prepared_chain.get('response')
    if response is not None:
        return response

    stats = prepared_chain['stats']
    warning = prepared_chain['warning']
    length = int(prepared_chain['length'])
    chain_nodes = prepared_chain['chain_nodes']
    chain_ids = prepared_chain['chain_ids']
    flag_assignments = prepared_chain['flag_assignments']
    debug_dag = bool(prepared_chain['debug_dag'])
    dag_debug = prepared_chain['dag_debug']
    flow_valid = bool(prepared_chain['flow_valid'])
    flow_errors = prepared_chain['flow_errors']
    flow_errors_detail = prepared_chain['flow_errors_detail']
    flags_enabled = bool(prepared_chain['flags_enabled'])
    run_generators = bool(prepared_chain['run_generators'])

    _gen_by_id: dict[str, dict[str, Any]] = {}

    remote_prepare = _prepare_remote_generator_execution(
        deps,
        run_generators=run_generators,
        flow_run_remote=flow_run_remote,
        flow_remote_forced=flow_remote_forced,
        flow_core_cfg=flow_core_cfg,
        flag_assignments=flag_assignments,
        flow_progress=_flow_progress,
    )
    response = remote_prepare.get('response')
    if response is not None:
        return response
    flow_run_remote = bool(remote_prepare.get('flow_run_remote'))
    flow_core_cfg = remote_prepare.get('flow_core_cfg') if isinstance(remote_prepare.get('flow_core_cfg'), dict) else flow_core_cfg
    flow_remote_repo_dir = str(remote_prepare.get('flow_remote_repo_dir') or '') or None

    generator_runtime_state = _prepare_generator_runtime_state(
        deps=deps,
        backend=backend,
        helpers=_flow_prepare_preview_helpers,
        preview=preview,
        chain_ids=chain_ids,
        chain_nodes=chain_nodes,
        flag_assignments=flag_assignments,
        flags_enabled=flags_enabled,
        run_generators=run_generators,
        scenario_label=scenario_label,
        scenario_norm=scenario_norm,
        base_plan_path=base_plan_path,
    )
    response = generator_runtime_state.get('response')
    if response is not None:
        return response

    flag_assignments = generator_runtime_state['flag_assignments']
    _gen_by_id = generator_runtime_state['gen_by_id']
    flag_seed_epoch = generator_runtime_state['flag_seed_epoch']

    runtime_adapters = _build_runtime_adapters(
        helpers=_flow_prepare_preview_helpers,
        backend=backend,
        scenario_norm=scenario_norm,
        flag_seed_epoch=flag_seed_epoch,
    )

    host_by_id = generator_runtime_state['host_by_id']

    execution_state = _execute_or_prepare_assignments(
        deps=deps,
        helpers=_flow_prepare_preview_helpers,
        preview=preview,
        host_by_id=host_by_id,
        gen_by_id=_gen_by_id,
        flag_assignments=flag_assignments,
        run_generators=run_generators,
        flow_run_remote=flow_run_remote,
        flow_core_cfg=flow_core_cfg,
        flow_remote_repo_dir=flow_remote_repo_dir,
        started_at=started_at,
        total_timeout_s=total_timeout_s,
        best_effort=best_effort,
        length=length,
        stats=stats,
        chain_nodes=chain_nodes,
        base_plan_path=base_plan_path,
        scenario_label=scenario_label,
        scenario_norm=scenario_norm,
        backend=backend,
        flow_default_generator_config=runtime_adapters['flow_default_generator_config'],
        flow_try_run_generator=runtime_adapters['flow_try_run_generator'],
        flow_try_run_generator_remote=runtime_adapters['flow_try_run_generator_remote'],
        preview_host_ip4=runtime_adapters['preview_host_ip4'],
        redact_kv_for_ui=runtime_adapters['redact_kv_for_ui'],
        flow_stage_file_inputs_for_generator=runtime_adapters['flow_stage_file_inputs_for_generator'],
    )
    response = execution_state.get('response')
    if response is not None:
        return response

    flag_assignments = execution_state['flag_assignments']
    created_run_dirs = execution_state['created_run_dirs']
    failed_run_dirs = execution_state['failed_run_dirs']
    progress_log = execution_state['progress_log']
    generation_failures = execution_state['generation_failures']
    generation_skipped = execution_state['generation_skipped']
    generator_runs = execution_state['generator_runs']
    return _finalize_prepare_preview_response(
        deps=deps,
        helpers=_flow_prepare_preview_helpers,
        flag_assignments=flag_assignments,
        run_generators_request=run_generators_request,
        mode=mode,
        base_plan_path=base_plan_path,
        scenario_label=scenario_label,
        scenario_norm=scenario_norm,
        length=length,
        requested_length=requested_length,
        chain_nodes=chain_nodes,
        flags_enabled=flags_enabled,
        flow_valid=flow_valid,
        flow_errors=flow_errors,
        meta=meta,
        preview=preview,
        host_by_id=host_by_id,
        preview_host_ip4=runtime_adapters['preview_host_ip4'],
        created_run_dirs=created_run_dirs,
        failed_run_dirs=failed_run_dirs,
        cleanup_generated_artifacts=cleanup_generated_artifacts,
        stats=stats,
        best_effort=best_effort,
        started_at=started_at,
        generator_runs=generator_runs,
        progress_log=progress_log,
        generation_failures=generation_failures,
        generation_skipped=generation_skipped,
        debug_dag=debug_dag,
        dag_debug=dag_debug,
        warning=warning,
        backend=backend,
        flow_errors_detail=flow_errors_detail,
    )


def execute(*, backend: Any):
    return execute_impl(backend=backend)