from __future__ import annotations

from typing import Any, Callable

from flask import jsonify, request


def register(
    app,
    *,
    purge_run_history_for_scenario: Callable[[str, bool], int],
    purge_planner_state_for_scenarios: Callable[[list[str]], int],
    purge_plan_artifacts_for_scenarios: Callable[[list[str]], int],
    remove_scenarios_from_catalog: Callable[[list[str]], dict[str, Any]],
    delete_saved_scenario_xml_artifacts: Callable[[list[str]], dict[str, Any]],
    remove_scenarios_from_all_editor_snapshots: Callable[[list[str]], dict[str, Any]],
    logger=None,
) -> None:
    """Register scenario purge/delete routes extracted from app_backend."""

    log = logger or getattr(app, "logger", None)

    @app.route('/purge_history_for_scenario', methods=['POST'])
    def purge_history_for_scenario():
        try:
            data = request.get_json(silent=True) or {}
            name = (data.get('name') or '').strip()
            if not name:
                return jsonify({'removed': 0}), 200
            removed = purge_run_history_for_scenario(name, delete_artifacts=True)
            planner_removed = purge_planner_state_for_scenarios([name])
            plans_removed = purge_plan_artifacts_for_scenarios([name])
            return jsonify({
                'removed': removed,
                'planner_removed': planner_removed,
                'plans_removed': plans_removed,
            })
        except Exception as e:
            return jsonify({'removed': 0, 'error': str(e)}), 200

    @app.route('/delete_scenarios', methods=['POST'])
    def delete_scenarios():
        """Persist scenario deletions across refresh."""
        try:
            data = request.get_json(silent=True) or {}
            raw_names = data.get('names')
            if isinstance(raw_names, str):
                names = [raw_names]
            elif isinstance(raw_names, list):
                names = [n for n in raw_names if isinstance(n, (str, int, float))]
            else:
                names = []
            names = [str(n).strip() for n in names if str(n).strip()]
            if not names:
                return jsonify({'ok': False, 'error': 'Missing scenario names'}), 400

            result = remove_scenarios_from_catalog(names)
            artifacts = delete_saved_scenario_xml_artifacts(names)
            snapshots = remove_scenarios_from_all_editor_snapshots(names)
            planner_removed = purge_planner_state_for_scenarios(names)
            plans_removed = purge_plan_artifacts_for_scenarios(names)

            history_removed = 0
            try:
                for nm in names:
                    try:
                        history_removed += purge_run_history_for_scenario(str(nm), delete_artifacts=True)
                    except Exception:
                        continue
            except Exception:
                history_removed = history_removed

            return jsonify({
                'ok': True,
                **result,
                **artifacts,
                **snapshots,
                'history_removed': history_removed,
                'planner_removed': planner_removed,
                'plans_removed': plans_removed,
            })
        except Exception as e:
            try:
                if log is not None:
                    log.exception('[delete_scenarios] failed: %s', e)
            except Exception:
                pass
            return jsonify({'ok': False, 'error': str(e)}), 500
