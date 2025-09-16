import os
import re
import shutil
import subprocess
import io
import json
import datetime
import time
import uuid
from typing import Dict, Any
import subprocess
import sys
import re
import xml.etree.ElementTree as ET
from lxml import etree as LET  # XML validation
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, Response, jsonify
from werkzeug.utils import secure_filename
import csv
from pathlib import Path
import logging
import logging
import zipfile

ALLOWED_EXTENSIONS = {'xml'}

app = Flask(__name__)
app.secret_key = 'coretopogenweb'
try:
    app.logger.setLevel(logging.DEBUG)
except Exception:
    pass
try:
    app.logger.setLevel(logging.DEBUG)
except Exception:
    pass

# ------------- Environment paths (.env/paths.json with env overrides) -------------
_ENV_PATHS_CACHE: Dict[str, str] | None = None

def _load_env_paths() -> Dict[str, str]:
    global _ENV_PATHS_CACHE
    if _ENV_PATHS_CACHE is not None:
        return _ENV_PATHS_CACHE
    repo_root = _get_repo_root()
    defaults = {
        'VULN_BASE_DIR': '/tmp/vulns',
        'VULN_REPO_SUBDIR': 'repo',
        'TRAFFIC_DIR': '/tmp/traffic',
        'SEGMENTATION_DIR': '/tmp/segmentation',
        'REPORTS_DIR': os.path.join(repo_root, 'reports'),
        'UPLOADS_DIR': os.path.join(repo_root, 'uploads'),
        'OUTPUTS_DIR': os.path.join(repo_root, 'outputs'),
    }
    cfg = {}
    try:
        p = os.path.join(repo_root, '.env', 'paths.json')
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as f:
                cfg = json.load(f) or {}
    except Exception:
        cfg = {}
    out: Dict[str, str] = {}
    for k, dv in defaults.items():
        val = os.environ.get(k, cfg.get(k, dv))
        # Resolve to absolute for repo-root relative paths
        if not os.path.isabs(val):
            # Treat as relative to repo root
            val = os.path.abspath(os.path.join(repo_root, val))
        out[k] = val
    _ENV_PATHS_CACHE = out
    return out


def _vuln_base_dir() -> str:
    return _load_env_paths().get('VULN_BASE_DIR')


def _vuln_repo_subdir() -> str:
    return _load_env_paths().get('VULN_REPO_SUBDIR') or 'repo'


def _traffic_dir() -> str:
    return _load_env_paths().get('TRAFFIC_DIR')


def _segmentation_dir() -> str:
    return _load_env_paths().get('SEGMENTATION_DIR')


def _reports_dir() -> str:
    return _load_env_paths().get('REPORTS_DIR')


def _uploads_dir() -> str:
    return _load_env_paths().get('UPLOADS_DIR')


def _outputs_dir() -> str:
    return _load_env_paths().get('OUTPUTS_DIR')


# Environment-configurable CORE daemon location (useful inside Docker)
CORE_HOST = os.environ.get('CORE_HOST', 'localhost')
try:
    CORE_PORT = int(os.environ.get('CORE_PORT', '50051'))
except Exception:
    CORE_PORT = 50051

def _default_core_dict():
    return {"host": CORE_HOST, "port": CORE_PORT}

def _get_repo_root() -> str:
    """Return absolute path to project root (parent of this webapp directory)."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def _get_cli_script_path() -> str:
    """Return absolute path to config2scen_core_grpc.py script."""
    return os.path.join(_get_repo_root(), 'config2scen_core_grpc.py')

# Now that helpers can resolve repo root, configure upload folder
UPLOAD_FOLDER = _uploads_dir()
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

UPLOAD_FOLDER = _uploads_dir()
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# In-memory registry for async runs
RUNS: Dict[str, Dict[str, Any]] = {}

# Run history persistence (simple JSON log)
RUN_HISTORY_PATH = os.path.join(_outputs_dir(), 'run_history.json')

def _load_run_history():
    try:
        if os.path.exists(RUN_HISTORY_PATH):
            with open(RUN_HISTORY_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def _append_run_history(entry: dict):
    history = _load_run_history()
    history.append(entry)
    os.makedirs(os.path.dirname(RUN_HISTORY_PATH), exist_ok=True)
    tmp = RUN_HISTORY_PATH + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2)
        os.replace(tmp, RUN_HISTORY_PATH)
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def _extract_report_path_from_text(text: str) -> str | None:
    """Parse CLI stdout/stderr text to extract the report path if logged.
    Looks for a line like: 'Scenario report written to /abs/path/report.md'
    """
    try:
        if not text:
            return None
        for line in text.splitlines():
            line = line.strip()
            if 'Scenario report written to ' in line:
                idx = line.find('Scenario report written to ')
                if idx >= 0:
                    path = line[idx + len('Scenario report written to '):].strip()
                    # strip trailing punctuation if any
                    path = path.rstrip('.;')
                    return path
    except Exception:
        pass
    return None

def _find_latest_report_path() -> str | None:
    """Find the most recent scenario_report_*.md under repo_root/reports."""
    try:
        base = _reports_dir()
        if not os.path.isdir(base):
            return None
        cands = []
        for name in os.listdir(base):
            if not name.startswith('scenario_report_') or not name.endswith('.md'):
                continue
            p = os.path.join(base, name)
            try:
                st = os.stat(p)
                cands.append((st.st_mtime, p))
            except Exception:
                continue
        if not cands:
            return None
        cands.sort(key=lambda x: x[0], reverse=True)
        return cands[0][1]
    except Exception:
        return None

def _scenario_names_from_xml(xml_path: str) -> list[str]:
    names: list[str] = []
    try:
        if not xml_path or not os.path.exists(xml_path):
            return names
        data = _parse_scenarios_xml(xml_path)
        for scen in data.get('scenarios', []):
            nm = scen.get('name')
            if nm and nm not in names:
                names.append(nm)
    except Exception:
        pass
    return names

def _extract_report_path_from_text(text: str) -> str | None:
    """Parse CLI output to extract a generated report path.

    The modern CLI (core_topo_gen.cli) logs a line like:
        "Scenario report written to /abs/path/reports/scenario_report_<ts>.md"
    """
    if not text:
        return None
    m = re.search(r"Scenario report written to\s+(.+)", text)
    if m:
        path = m.group(1).strip()
        # Trim trailing punctuation if any
        path = path.rstrip(' .')
        # Make absolute if not already
        if not os.path.isabs(path):
            repo_root = _get_repo_root()
            path = os.path.abspath(os.path.join(repo_root, path))
        if os.path.exists(path):
            return path
    return None

def _find_latest_report_path(since_ts: float | None = None) -> str | None:
    """Find the most recent scenario_report_*.md under the repo reports directory.

    If since_ts is provided (epoch seconds), prefer files modified after this time.
    """
    try:
        report_dir = _reports_dir()
        if not os.path.isdir(report_dir):
            return None
        cands = []
        for name in os.listdir(report_dir):
            if not name.endswith('.md'):
                continue
            if not name.startswith('scenario_report_'):
                continue
            p = os.path.join(report_dir, name)
            try:
                st = os.stat(p)
                if since_ts is None or st.st_mtime >= max(0.0, float(since_ts) - 5.0):
                    cands.append((st.st_mtime, p))
            except Exception:
                continue
        if not cands:
            return None
        cands.sort(key=lambda x: x[0], reverse=True)
        return cands[0][1]
    except Exception:
        return None

def _extract_session_id_from_text(text: str) -> str | None:
    """Parse CLI logs for the session id marker emitted by core_topo_gen.cli.

    Expected line:
        CORE_SESSION_ID: <id>
    """
    try:
        if not text:
            return None
        m = re.search(r"CORE_SESSION_ID:\s*(\S+)", text)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None

def _safe_add_to_zip(zf: zipfile.ZipFile, abs_path: str, arcname: str) -> None:
    try:
        if abs_path and os.path.exists(abs_path):
            zf.write(abs_path, arcname)
    except Exception:
        pass

def _gather_scripts_into_zip(zf: zipfile.ZipFile) -> int:
    """Collect generated traffic and segmentation artifacts into the provided zip file.

    Returns the count of files added.
    """
    added = 0
    # Traffic
    try:
        tdir = _traffic_dir()
        if os.path.isdir(tdir):
            # include summary first
            sp = os.path.join(tdir, "traffic_summary.json")
            if os.path.exists(sp):
                _safe_add_to_zip(zf, sp, os.path.join("traffic", "traffic_summary.json")); added += 1
            for name in os.listdir(tdir):
                if not name.startswith("traffic_"):
                    continue
                ap = os.path.join(tdir, name)
                if os.path.isfile(ap):
                    _safe_add_to_zip(zf, ap, os.path.join("traffic", name)); added += 1
    except Exception:
        pass
    # Segmentation
    try:
        sdir = _segmentation_dir()
        if os.path.isdir(sdir):
            sp = os.path.join(sdir, "segmentation_summary.json")
            if os.path.exists(sp):
                _safe_add_to_zip(zf, sp, os.path.join("segmentation", "segmentation_summary.json")); added += 1
            for name in os.listdir(sdir):
                if not (name.startswith("seg_") and name.endswith(".py")):
                    continue
                ap = os.path.join(sdir, name)
                if os.path.isfile(ap):
                    _safe_add_to_zip(zf, ap, os.path.join("segmentation", name)); added += 1
    except Exception:
        pass
    return added

def _build_full_scenario_archive(out_dir: str, scenario_xml_path: str | None, report_path: str | None, pre_xml_path: str | None, post_xml_path: str | None, run_id: str | None = None) -> str | None:
    """Create a zip bundle that includes the scenario XML, pre/post session XML, report, and any generated scripts.

    Returns the path to the created zip, or None on failure.
    """
    try:
        os.makedirs(out_dir, exist_ok=True)
        stem = datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        if run_id:
            stem = f"{stem}-{run_id[:8]}"
        zip_path = os.path.join(out_dir, f"full_scenario_{stem}.zip")
        with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            # Add top-level artifacts if present
            if scenario_xml_path and os.path.exists(scenario_xml_path):
                _safe_add_to_zip(zf, scenario_xml_path, "scenario.xml")
            if report_path and os.path.exists(report_path):
                _safe_add_to_zip(zf, report_path, os.path.join("report", os.path.basename(report_path)))
            if pre_xml_path and os.path.exists(pre_xml_path):
                _safe_add_to_zip(zf, pre_xml_path, os.path.join("core-session", os.path.basename(pre_xml_path)))
            if post_xml_path and os.path.exists(post_xml_path):
                _safe_add_to_zip(zf, post_xml_path, os.path.join("core-session", os.path.basename(post_xml_path)))
            # Add generated scripts and summaries
            _gather_scripts_into_zip(zf)
        return zip_path if os.path.exists(zip_path) else None
    except Exception:
        return None

# Data sources state
DATA_SOURCES_DIR = os.path.abspath(os.path.join('..', 'data_sources'))
DATA_STATE_PATH = os.path.join(DATA_SOURCES_DIR, '_state.json')
os.makedirs(DATA_SOURCES_DIR, exist_ok=True)

def _load_data_sources_state():
    try:
        if not os.path.exists(DATA_STATE_PATH):
            return {"sources": []}
        with open(DATA_STATE_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Legacy format
        if isinstance(data, dict) and 'enabled' in data and 'sources' not in data:
            return {"sources": []}
        if 'sources' not in data:
            data['sources'] = []
        return data
    except Exception:
        return {"sources": []}

def _save_data_sources_state(state):
    tmp = DATA_STATE_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, DATA_STATE_PATH)

def _validate_csv(file_path: str, max_bytes: int = 2_000_000):
    try:
        st = os.stat(file_path)
        if st.st_size > max_bytes:
            return False, f"File too large (> {max_bytes} bytes)"
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            rows = []
            for i, row in enumerate(reader):
                if i > 10000:
                    break
                rows.append(row)
        if len(rows) < 2:
            return False, "CSV must have header + at least one data row"
        widths = {len(r) for r in rows}
        if len(widths) != 1:
            return False, "Inconsistent column counts"
        return True, f"{len(rows)-1} rows"
    except Exception as e:
        return False, str(e)

# --- Data Source CSV schema enforcement ---
REQUIRED_DS_COLUMNS = ["Name", "Path", "Type", "Startup", "Vector"]
OPTIONAL_DS_DEFAULTS = {
    "CVE": "n/a",
    "Description": "n/a",
    "References": "n/a",
}
ALLOWED_TYPE_VALUES = {"artifact", "docker", "docker-compose", "misconfig", "incompetence"}
ALLOWED_VECTOR_VALUES = {"local", "remote"}

def _validate_and_normalize_data_source_csv(file_path: str, max_bytes: int = 2_000_000, *, skip_invalid: bool = False):
    """Validate uploaded CSV for Data Sources and normalize optional columns.

    Rules:
    - Must be under max size, have header + at least one data row, and consistent row widths (after normalization step below).
    - Must include all REQUIRED_DS_COLUMNS (exact names).
    - Optional columns from OPTIONAL_DS_DEFAULTS will be appended to header if missing, and populated per-row with defaults if empty/missing.
    - Type values must be one of ALLOWED_TYPE_VALUES (case-insensitive), Vector values one of ALLOWED_VECTOR_VALUES (case-insensitive).
    - Name, Path, Startup must be non-empty strings.

        Parameters:
            file_path: path to CSV file
            max_bytes: size cap
            skip_invalid: if True, invalid data rows are skipped instead of failing the whole import.

        Returns: (ok: bool, note_or_error: str, rows: list[list[str]]|None, skipped_rows: list[int])
            ok: overall success
            note_or_error: description / counts; if skip_invalid True may include skip summary
            rows: normalized rows including header (only valid rows if skipping)
            skipped_rows: list of 1-based data row indices (relative to first data line after header) that were skipped
    """
    try:
        st = os.stat(file_path)
        if st.st_size > max_bytes:
            return False, f"File too large (> {max_bytes} bytes)", None
        # Load CSV
        rows: list[list[str]] = []
        with open(file_path, 'r', encoding='utf-8', errors='replace', newline='') as f:
            rdr = csv.reader(f)
            for i, row in enumerate(rdr):
                if i > 10000:
                    break
                rows.append([str(c) if c is not None else '' for c in row])
        if len(rows) < 2:
            return False, "CSV must have header + at least one data row", None, []
        header = rows[0]
        # Strip UTF-8 BOM if present in first cell
        if header and header[0].startswith('\ufeff'):
            header[0] = header[0].lstrip('\ufeff')
        # Ensure required headers exist
        # Case-insensitive match for required headers
        header_lower_map = {h.lower(): h for h in header}
        missing = [h for h in REQUIRED_DS_COLUMNS if h.lower() not in header_lower_map]
        # Normalize header casing to canonical names (only for required columns)
        if not missing:
            for req in REQUIRED_DS_COLUMNS:
                real = header_lower_map.get(req.lower())
                if real != req:
                    # rename in place
                    idx = header.index(real)
                    header[idx] = req
        if missing:
            return False, f"Missing required column(s): {', '.join(missing)}", None, []
        # Append optional headers if missing
        for opt_col, default in OPTIONAL_DS_DEFAULTS.items():
            if opt_col not in header:
                header.append(opt_col)
        # Normalize all rows to header length
        width = len(header)
        norm_rows: list[list[str]] = [header]
        # Build column index map
        col_idx = {name: header.index(name) for name in header}
        # Validate and fill rows
        errs: list[str] = []
        skipped_rows: list[int] = []
        for data_idx, row in enumerate(rows[1:], start=1):  # data_idx: 1-based index of data row (excluding header)
            r = list(row)
            if len(r) < width:
                r = r + [''] * (width - len(r))
            elif len(r) > width:
                r = r[:width]
            # Pull fields
            name = (r[col_idx['Name']]).strip()
            path = (r[col_idx['Path']]).strip()
            typ = (r[col_idx['Type']]).strip()
            startup = (r[col_idx['Startup']]).strip()
            vector = (r[col_idx['Vector']]).strip()
            row_err = False
            if not name:
                errs.append(f"row {data_idx}: Name is required"); row_err = True
            if not path:
                errs.append(f"row {data_idx}: Path is required"); row_err = True
            if not startup:
                errs.append(f"row {data_idx}: Startup is required"); row_err = True
            if typ:
                if typ.lower() not in ALLOWED_TYPE_VALUES:
                    errs.append(f"row {data_idx}: Type '{typ}' not in {sorted(ALLOWED_TYPE_VALUES)}"); row_err = True
                else:
                    # Normalize to lower
                    r[col_idx['Type']] = typ.lower()
            else:
                errs.append(f"row {data_idx}: Type is required"); row_err = True
            if vector:
                if vector.lower() not in ALLOWED_VECTOR_VALUES:
                    errs.append(f"row {data_idx}: Vector '{vector}' not in {sorted(ALLOWED_VECTOR_VALUES)}"); row_err = True
                else:
                    r[col_idx['Vector']] = vector.lower()
            else:
                errs.append(f"row {data_idx}: Vector is required"); row_err = True
            # Fill optionals with defaults if empty
            for opt_col, default in OPTIONAL_DS_DEFAULTS.items():
                if not r[col_idx[opt_col]].strip():
                    r[col_idx[opt_col]] = default
            if row_err and skip_invalid:
                skipped_rows.append(data_idx)
                continue
            norm_rows.append(r)
        if skip_invalid:
            if len(norm_rows) == 1:
                return False, "All data rows invalid", None, skipped_rows
            note_parts = [f"{len(norm_rows)-1} rows"]
            if skipped_rows:
                listed = ','.join(str(i) for i in skipped_rows[:20])
                extra = '' if len(skipped_rows) <= 20 else '...'
                note_parts.append(f"skipped {len(skipped_rows)} invalid row(s): {listed}{extra}")
            return True, ' | '.join(note_parts), norm_rows, skipped_rows
        else:
            if errs:
                return False, "; ".join(errs[:20]) + (" ..." if len(errs)>20 else ''), None, []
            return True, f"{len(norm_rows)-1} rows", norm_rows, []
    except Exception as e:
        return False, str(e), None, []

def _default_scenarios_payload():
    # Single default scenario with empty sections mirroring PyQt structure
    sections = [
        "Node Information", "Routing", "Services", "Traffic",
        "Events", "Vulnerabilities", "Segmentation"
    ]
    scen = {
        "name": "Scenario 1",
        "base": {"filepath": ""},
        "sections": {name: {
            "density": 0.5 if name != "Node Information" else None,
            "total_nodes": 1 if name == "Node Information" else None,
            "items": []
        } for name in sections},
        "notes": ""
    }
    return {"scenarios": [scen], "result_path": None, "core": _default_core_dict()}


def _grpc_save_current_session_xml(host: str, port: int, out_dir: str, session_id: str | None = None) -> str | None:
    """Attempt to connect to CORE daemon via gRPC and save the active session XML.

    This uses CoreGrpcClient.save_xml if available. If no active session exists
    or the gRPC client modules are unavailable, returns None silently.

    A timestamped filename core-session-<ts>.xml is written to out_dir.
    """
    try:
        from core.api.grpc.client import CoreGrpcClient  # type: ignore
    except Exception:
        app.logger.debug("gRPC CoreGrpcClient not available; skipping save_xml (host=%s port=%s)", host, port)
        return None
    address = f"{host}:{port}"
    ts = datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    os.makedirs(out_dir, exist_ok=True)
    # Pick first running/defined session if any; API lacks direct 'current' concept here.
    try:
        app.logger.debug("Connecting to CORE gRPC at %s (requested session_id=%s)", address, session_id)
        client = CoreGrpcClient(address=address)
        client.connect()
        try:
            sessions = client.get_sessions()
            if not sessions:
                app.logger.info("No CORE sessions found at %s; cannot save session XML", address)
                return None
            # If a specific session id is requested, select it; otherwise default to first
            target = None
            if session_id is not None:
                for s in sessions:
                    sid = getattr(s, 'id', None) or getattr(s, 'session_id', None)
                    if str(sid) == str(session_id):
                        target = s
                        break
                if target is None:
                    app.logger.warning("Requested session_id=%s not found; defaulting to first session", session_id)
                    target = sessions[0]
            else:
                target = sessions[0]
            session_id = getattr(target, 'id', None) or getattr(target, 'session_id', None)
            if session_id is None:
                app.logger.warning("Selected CORE session has no id; aborting save_xml")
                return None
            out_path = os.path.join(out_dir, f"core-session-{session_id}-{ts}.xml")
            try:
                app.logger.info("Invoking save_xml(session_id=%s) -> %s", session_id, out_path)
                client.save_xml(session_id=session_id, file_path=out_path)
            except Exception as e:
                app.logger.warning("save_xml failed for session %s at %s: %s", session_id, address, e)
                return None
            if os.path.exists(out_path):
                # Validate that it's a CORE XML and not our editor format
                try:
                    ok, errs = _validate_core_xml(out_path)
                except Exception as e:
                    app.logger.warning("CORE XML validation raised exception for %s: %s", out_path, e)
                    ok = False
                if ok:
                    try:
                        size = os.stat(out_path).st_size
                    except Exception:
                        size = -1
                    app.logger.info("Saved valid CORE session XML (session_id=%s) at %s (%s bytes)", session_id, out_path, size if size >= 0 else '?')
                    return out_path
                else:
                    app.logger.warning("Saved XML failed CORE validation; deleting file %s. Errors: %s", out_path, errs if 'errs' in locals() else '(unknown)')
                    try:
                        os.remove(out_path)
                    except Exception:
                        pass
            return None
        finally:
            try:
                client.close()
            except Exception:
                pass
    except Exception:
        return None

def _attach_base_upload(payload: Dict[str, Any]):
    """Ensure payload['base_upload'] is present if first scenario has a base filepath referencing an existing file.
    Performs validation to set valid flag. Does nothing if already present.
    """
    try:
        if payload.get('base_upload'):
            return
        scen_list = payload.get('scenarios') or []
        if not scen_list:
            return
        base_path = scen_list[0].get('base', {}).get('filepath') or ''
        if not base_path or not os.path.exists(base_path):
            return
        ok, _errs = _validate_core_xml(base_path)
        payload['base_upload'] = { 'path': base_path, 'valid': bool(ok) }
    except Exception:
        pass


def _parse_scenarios_xml(path):
    data = {"scenarios": []}
    tree = ET.parse(path)
    root = tree.getroot()
    if root.tag != "Scenarios":
        # Fallback: if file is a single ScenarioEditor, wrap
        if root.tag == "ScenarioEditor":
            scen = _parse_scenario_editor(root)
            scen["name"] = os.path.splitext(os.path.basename(path))[0]
            data["scenarios"].append(scen)
            return data
        raise ValueError("Root element must be <Scenarios> or <ScenarioEditor>")
    for scen_el in root.findall("Scenario"):
        scen = {"name": scen_el.get("name", "Scenario")}
        se = scen_el.find("ScenarioEditor")
        if se is None:
            continue
        scen.update(_parse_scenario_editor(se))
        data["scenarios"].append(scen)
    return data


def _parse_scenario_editor(se):
    scen = {"base": {"filepath": ""}, "sections": {}, "notes": ""}
    base = se.find("BaseScenario")
    if base is not None:
        scen["base"]["filepath"] = base.get("filepath", "")
    # Sections
    for sec in se.findall("section"):
        name = sec.get("name", "")
        if not name:
            continue
        entry = {"density": None, "total_nodes": None, "items": []}
        if name == "Node Information":
            tn = sec.get("total_nodes")
            if tn is not None:
                try:
                    entry["total_nodes"] = int(tn)
                except Exception:
                    entry["total_nodes"] = 1
        else:
            dens = sec.get("density")
            entry["density"] = float(dens) if dens is not None else 0.5
        for item in sec.findall("item"):
            d = {
                "selected": item.get("selected", "Random"),
                "factor": float(item.get("factor", "1.0")),
            }
            if name == "Events":
                d["script_path"] = item.get("script_path", "")
            if name == "Traffic":
                d.update({
                    "pattern": item.get("pattern", "continuous"),
                    "rate_kbps": float(item.get("rate_kbps", "64.0")),
                    "period_s": float(item.get("period_s", "1.0")),
                    "jitter_pct": float(item.get("jitter_pct", "10.0")),
                })
            if name == "Vulnerabilities":
                # Extra attributes for Vulnerabilities section
                sel = (d.get("selected") or "").strip()
                if sel == "Type/Vector":
                    d["v_type"] = item.get("v_type", "Random")
                    d["v_vector"] = item.get("v_vector", "Random")
                elif sel == "Specific":
                    d["v_name"] = item.get("v_name", "")
                    d["v_path"] = item.get("v_path", "")
                    # Default count to 1 if missing/invalid
                    try:
                        d["v_count"] = int(item.get("v_count", "1"))
                    except Exception:
                        d["v_count"] = 1
                # Persist metric choice if present (Weight or Count)
                vm = item.get("v_metric")
                if vm:
                    d["v_metric"] = vm
            # Generic metric/count for all sections (including Vulnerabilities)
            try:
                vm_generic = item.get("v_metric")
                if vm_generic and vm_generic in ("Weight", "Count"):
                    d["v_metric"] = vm_generic
                vc_generic = item.get("v_count")
                if vc_generic is not None:
                    try:
                        d["v_count"] = int(vc_generic)
                    except Exception:
                        d["v_count"] = 1
            except Exception:
                pass
            entry["items"].append(d)
        scen["sections"][name] = entry
    # Notes
    notes_sec = None
    for sec in se.findall("section"):
        if sec.get("name") == "Notes":
            notes_sec = sec; break
    if notes_sec is not None:
        notes_el = notes_sec.find("notes")
        if notes_el is not None and notes_el.text:
            scen["notes"] = notes_el.text
    return scen


def _build_scenarios_xml(data_dict: dict) -> ET.ElementTree:
    root = ET.Element("Scenarios")
    for scen in data_dict.get("scenarios", []):
        scen_el = ET.SubElement(root, "Scenario")
        scen_el.set("name", scen.get("name", "Scenario"))
        se = ET.SubElement(scen_el, "ScenarioEditor")
        base = ET.SubElement(se, "BaseScenario")
        base.set("filepath", scen.get("base", {}).get("filepath", ""))
        # Sections in desired order
        order = [
            "Node Information", "Routing", "Services", "Traffic",
            "Events", "Vulnerabilities", "Segmentation", "Notes"
        ]
        for name in order:
            if name == "Notes":
                sec_el = ET.SubElement(se, "section", name="Notes")
                ne = ET.SubElement(sec_el, "notes")
                ne.text = scen.get("notes", "") or ""
                continue
            sec = scen.get("sections", {}).get(name, None)
            if sec is None:
                continue
            sec_el = ET.SubElement(se, "section", name=name)
            if name == "Node Information":
                tn = sec.get("total_nodes")
                if tn is not None:
                    sec_el.set("total_nodes", str(int(tn)))
            else:
                dens = sec.get("density")
                if dens is not None:
                    sec_el.set("density", f"{float(dens):.3f}")
            for item in sec.get("items", []):
                it = ET.SubElement(sec_el, "item")
                it.set("selected", str(item.get('selected', 'Random')))
                it.set("factor", f"{float(item.get('factor', 1.0)):.3f}")
                if name == "Events":
                    sp = item.get('script_path', "")
                    if sp:
                        it.set("script_path", sp)
                if name == "Traffic":
                    it.set("pattern", str(item.get('pattern', 'continuous')))
                    it.set("rate_kbps", f"{float(item.get('rate_kbps', 64.0)):.1f}")
                    it.set("period_s", f"{float(item.get('period_s', 1.0)):.1f}")
                    it.set("jitter_pct", f"{float(item.get('jitter_pct', 10.0)):.1f}")
                if name == "Vulnerabilities":
                    sel = str(item.get('selected', 'Random'))
                    if sel == 'Type/Vector':
                        vt = item.get('v_type')
                        vv = item.get('v_vector')
                        if vt:
                            it.set('v_type', str(vt))
                        if vv:
                            it.set('v_vector', str(vv))
                    elif sel == 'Specific':
                        vn = item.get('v_name')
                        vp = item.get('v_path')
                        if vn:
                            it.set('v_name', str(vn))
                        if vp:
                            it.set('v_path', str(vp))
                # Save metric selection and count (for all sections)
                vm_any = item.get('v_metric')
                if vm_any:
                    it.set('v_metric', str(vm_any))
                if (item.get('v_metric') == 'Count') or (name == 'Vulnerabilities' and str(item.get('selected', '')) == 'Specific'):
                    vc_any = item.get('v_count')
                    try:
                        if vc_any is not None:
                            it.set('v_count', str(int(vc_any)))
                    except Exception:
                        pass
    return ET.ElementTree(root)


def _validate_core_xml(xml_path: str):
    """Validate the scenario XML against the CORE XML XSD. Returns (ok, errors_text)."""
    try:
        # Derive project root relative to this file (../) then the validation directory
        here = os.path.abspath(os.path.dirname(__file__))
        repo_root = os.path.abspath(os.path.join(here, '..'))
        xsd_path = os.path.join(repo_root, 'validation', 'core-xml-syntax', 'corexml_codebased.xsd')
        # Fallback: if not found, try relative to current working directory (for unusual run contexts)
        if not os.path.exists(xsd_path):
            alt = os.path.abspath(os.path.join(os.getcwd(), 'validation', 'core-xml-syntax', 'corexml_codebased.xsd'))
            if os.path.exists(alt):
                xsd_path = alt
        if not os.path.exists(xsd_path):
            return False, f"Schema not found: {xsd_path}"
        with open(xsd_path, 'rb') as f:
            schema_doc = LET.parse(f)
        schema = LET.XMLSchema(schema_doc)
        parser = LET.XMLParser(schema=schema)
        LET.parse(xml_path, parser)
        return True, ''
    except LET.XMLSyntaxError as e:
        lines = []
        for err in e.error_log:
            lines.append(f"{err.level_name} L{err.line}:C{err.column} - {err.message}")
        return False, "\n".join(lines) or str(e)
    except Exception as e:
        return False, str(e)


def _analyze_core_xml(xml_path: str) -> Dict[str, Any]:
    """Extract basic details from a CORE scenario XML for a summary view."""
    info: Dict[str, Any] = {}
    try:
        tree = LET.parse(xml_path)
        root = tree.getroot()
        # generic helpers
        def attrs(el, *names):
            return {n: el.get(n) for n in names if el.get(n) is not None}

        devices = root.findall('.//device')
        networks = root.findall('.//network')
        links_parent = root.find('.//links')
        links = []
        if links_parent is not None:
            links = list(links_parent)
        services = root.findall('.//service')

        # Build maps for easy lookup
        id_to_name: Dict[str, str] = {}
        id_to_type: Dict[str, str] = {}
        id_to_services: Dict[str, list] = {}
        for d in devices:
            did = d.get('id') or ''
            id_to_name[did] = d.get('name') or did
            id_to_type[did] = d.get('type') or ''
            # services within this device
            svcs = [s.get('name') for s in d.findall('./services/service') if s.get('name')]
            id_to_services[did] = svcs

        # Adjacency from links
        adj: Dict[str, set] = { (d.get('id') or ''): set() for d in devices }
        for link in links:
            n1 = link.get('node1')
            n2 = link.get('node2')
            # If node1/node2 missing, try infer from iface1/iface2 IPs by matching to device ids present in attributes (common CORE format already provides node1/node2, so this is a no-op for valid samples)
            if not n1 or not n2:
                # Some variations may nest iface1/iface2 without node1/node2 on link; in such cases, skip as we cannot safely infer
                pass
            if n1 and n2:
                adj.setdefault(n1, set()).add(n2)
                adj.setdefault(n2, set()).add(n1)

        # Compose nodes list with linked names
        nodes = []
        for d in devices:
            did = d.get('id') or ''
            node = {
                'id': did,
                'name': d.get('name') or did,
                'type': d.get('type') or '',
                'services': id_to_services.get(did, []),
                'linked_nodes': sorted([id_to_name.get(x, x) for x in adj.get(did, set())], key=lambda x: x.lower()),
            }
            nodes.append(node)

        info.update({
            'nodes_count': len(devices),
            'networks_count': len(networks),
            'links_count': len(links),
            'services_count': len(services),
            'nodes': nodes,
        })
        # legacy fields kept for compatibility with any current UI that may still reference them
        info['devices'] = [attrs(d, 'id', 'name', 'type', 'class', 'image') for d in devices[:50]]
        info['networks'] = [attrs(n, 'id', 'name', 'type', 'model', 'mobility') for n in networks[:50]]
        info['links_sample'] = len(links[:100])
        # filesize
        try:
            st = os.stat(xml_path)
            info['file_size_bytes'] = st.st_size
        except Exception:
            pass
        return info
    except Exception as e:
        return {'error': str(e)}


@app.route('/', methods=['GET'])
def index():
    payload = _default_scenarios_payload()
    # Reconstruct base_upload if base filepath already present
    _attach_base_upload(payload)
    return render_template('index.html', payload=payload, logs="", xml_preview="")


@app.route('/load_xml', methods=['POST'])
def load_xml():
    file = request.files.get('scenarios_xml')
    if not file or file.filename == '':
        flash('No file selected.')
        return redirect(url_for('index'))
    if not allowed_file(file.filename):
        flash('Invalid file type. Only XML allowed.')
        return redirect(url_for('index'))
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file.save(filepath)
    try:
        payload = _parse_scenarios_xml(filepath)
        # add default CORE connection parameters
        if "core" not in payload:
            payload["core"] = _default_core_dict()
        payload["result_path"] = filepath
        _attach_base_upload(payload)
        xml_text = ""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                xml_text = f.read()
        except Exception:
            xml_text = ""
        return render_template('index.html', payload=payload, logs="", xml_preview=xml_text)
    except Exception as e:
        flash(f'Failed to parse XML: {e}')
        return redirect(url_for('index'))


@app.route('/save_xml', methods=['POST'])
def save_xml():
    data_str = request.form.get('scenarios_json')
    if not data_str:
        flash('No data received.')
        return redirect(url_for('index'))
    try:
        data = json.loads(data_str)
    except Exception as e:
        flash(f'Invalid JSON: {e}')
        return redirect(url_for('index'))
    try:
        tree = _build_scenarios_xml(data)
        ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        out_dir = os.path.join('outputs', f'scenarios-{ts}')
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, 'scenarios.xml')
        # Pretty print if lxml available else fallback
        try:
            from lxml import etree as LET  # type: ignore
            raw = ET.tostring(tree.getroot(), encoding='utf-8')
            lroot = LET.fromstring(raw)
            pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding='utf-8')
            with open(out_path, 'wb') as f:
                f.write(pretty)
        except Exception:
            tree.write(out_path, encoding='utf-8', xml_declaration=True)
        # Read back XML content for preview
        xml_text = ""
        try:
            with open(out_path, 'r', encoding='utf-8', errors='ignore') as f:
                xml_text = f.read()
        except Exception:
            xml_text = ""
        flash('Scenarios saved. You can download or run the CLI.')
        # Re-parse the saved XML to ensure the UI reflects exactly what was persisted
        try:
            payload = _parse_scenarios_xml(out_path)
            if "core" not in payload:
                payload["core"] = _default_core_dict()
            payload["result_path"] = out_path
        except Exception:
            payload = {"scenarios": data.get("scenarios", []), "result_path": out_path, "core": _default_core_dict()}
        _attach_base_upload(payload)
        return render_template('index.html', payload=payload, logs="", xml_preview=xml_text)
    except Exception as e:
        flash(f'Failed to save XML: {e}')
        return redirect(url_for('index'))


@app.route('/run_cli', methods=['POST'])
def run_cli():
    xml_path = request.form.get('xml_path')
    if not xml_path:
        flash('XML path missing. Save XML first.')
        return redirect(url_for('index'))
    # Always resolve to absolute path
    xml_path = os.path.abspath(xml_path)
    if not os.path.exists(xml_path):
        flash(f'XML path not found: {xml_path}')
        return redirect(url_for('index'))
    # Skip schema validation: format differs from CORE XML
    # Run gRPC CLI script (config2scen_core_grpc.py) instead of internal module
    try:
        # Attempt to parse current scenarios JSON (if present) to extract core host/port overrides
        core_host = '127.0.0.1'
        core_port = 50051
        try:
            # attempt to load previously saved payload for core info
            payload = _parse_scenarios_xml(xml_path)
            ch = payload.get('core', {}).get('host') if isinstance(payload.get('core'), dict) else None
            cp = payload.get('core', {}).get('port') if isinstance(payload.get('core'), dict) else None
            if ch: core_host = str(ch)
            if cp: core_port = int(cp)
        except Exception:
            pass
        app.logger.info("[sync] Running CLI with CORE %s:%s, xml=%s", core_host, core_port, xml_path)
        # Pre-save any existing active CORE session XML (best-effort) using derived host/port
        try:
            pre_dir = os.path.join(os.path.dirname(xml_path), 'core-pre')
            pre_saved = _grpc_save_current_session_xml(core_host, core_port, pre_dir)
            if pre_saved:
                flash(f'Captured current CORE session XML: {os.path.basename(pre_saved)}')
                app.logger.debug("[sync] Pre-run session XML saved to %s", pre_saved)
        except Exception:
            pass
        repo_root = _get_repo_root()
        # Invoke package CLI so it can generate reports under repo_root/reports
        proc = subprocess.run([
            'core-python', '-m', 'core_topo_gen.cli',
            '--xml', xml_path,
            '--host', core_host,
            '--port', str(core_port),
            '--verbose',
        ], cwd=repo_root, check=False, capture_output=True, text=True)
        logs = (proc.stdout or '') + ('\n' + proc.stderr if proc.stderr else '')
        app.logger.debug("[sync] CLI return code: %s", proc.returncode)
        # Report path (if generated by CLI): parse logs or fallback to latest under reports/
        report_md = _extract_report_path_from_text(logs) or _find_latest_report_path()
        if report_md:
            app.logger.info("[sync] Detected report path: %s", report_md)
        # Try to capture the exact session id from logs for precise post-run save
        session_id = _extract_session_id_from_text(logs)
        if session_id:
            app.logger.info("[sync] Detected CORE session id: %s", session_id)
        # Read XML for preview
        xml_text = ""
        try:
            with open(xml_path, 'r', encoding='utf-8', errors='ignore') as f:
                xml_text = f.read()
        except Exception:
            xml_text = ""
        run_success = False
        post_saved = None
        if proc.returncode != 0:
            flash('CLI finished with errors. See logs.')
        else:
            run_success = True
            if report_md and os.path.exists(report_md):
                flash('CLI completed. Report ready to download.')
            else:
                flash('CLI completed. No report found.')
            # Best-effort: save the active CORE session XML after successful run
            try:
                post_dir = os.path.join(os.path.dirname(xml_path), 'core-post')
                post_saved = _grpc_save_current_session_xml(core_host, core_port, post_dir, session_id=session_id)
                if post_saved:
                    flash(f'Captured post-run CORE session XML: {os.path.basename(post_saved)}')
                    app.logger.debug("[sync] Post-run session XML saved to %s", post_saved)
            except Exception:
                post_saved = None
        payload = _parse_scenarios_xml(xml_path)
        if "core" not in payload:
            payload["core"] = _default_core_dict()
        _attach_base_upload(payload)
        # Always use absolute xml_path for result_path fallback
        payload["result_path"] = report_md if (report_md and os.path.exists(report_md)) else xml_path
        # Append run history entry on success
        if run_success:
            try:
                scen_names = _scenario_names_from_xml(xml_path)
                # Build a Full Scenario bundle including scripts
                full_bundle = _build_full_scenario_archive(os.path.dirname(xml_path), xml_path, (report_md if (report_md and os.path.exists(report_md)) else None), (pre_saved if 'pre_saved' in locals() else None), post_saved, run_id=None)
                _append_run_history({
                    'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
                    'mode': 'sync',
                    # Only record session xml if we actually pulled it via gRPC
                    'xml_path': post_saved if (post_saved and os.path.exists(post_saved)) else None,
                    'post_xml_path': post_saved if (post_saved and os.path.exists(post_saved)) else None,
                    'scenario_xml_path': xml_path,
                    'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
                    'pre_xml_path': pre_saved if 'pre_saved' in locals() else None,
                    'full_scenario_path': full_bundle,
                    'returncode': proc.returncode,
                    'scenario_names': scen_names,
                })
            except Exception:
                pass
        return render_template('index.html', payload=payload, logs=logs, xml_preview=xml_text, run_success=run_success)
    except Exception as e:
        flash(f'Error running core-topo-gen: {e}')
        return redirect(url_for('index'))

@app.route('/download_report')
def download_report():
    result_path = request.args.get('path')
    if result_path and os.path.exists(result_path):
        try:
            app.logger.info("[download] serving file: %s", os.path.abspath(result_path))
        except Exception:
            pass
        return send_file(result_path, as_attachment=True)
    try:
        app.logger.warning("[download] file not found: %s", result_path)
    except Exception:
        pass
    flash('Report not found.')
    return redirect(url_for('index'))

@app.route('/reports')
def reports_page():
    raw = _load_run_history()
    enriched = []
    for entry in raw:
        e = dict(entry)
        # Keep xml_path as stored (session xml only if available)
        if 'scenario_names' not in e:
            e['scenario_names'] = _scenario_names_from_xml(e.get('xml_path'))
        enriched.append(e)
    enriched = sorted(enriched, key=lambda x: x.get('timestamp',''), reverse=True)
    # collect unique scenario names
    scen_names: list[str] = []
    for e in enriched:
        for n in e.get('scenario_names', []) or []:
            if n not in scen_names:
                scen_names.append(n)
    return render_template('reports.html', history=enriched, scenarios=scen_names)

@app.route('/reports_data')
def reports_data():
    raw = _load_run_history()
    enriched = []
    scen_names: set[str] = set()
    for entry in raw:
        e = dict(entry)
        # Keep xml_path as stored (session xml only if available)
        if 'scenario_names' not in e:
            e['scenario_names'] = _scenario_names_from_xml(e.get('xml_path'))
        for n in e.get('scenario_names', []) or []:
            scen_names.add(n)
        enriched.append(e)
    enriched = sorted(enriched, key=lambda x: x.get('timestamp',''), reverse=True)
    return jsonify({ 'history': enriched, 'scenarios': sorted(list(scen_names)) })


@app.route('/run_cli_async', methods=['POST'])
def run_cli_async():
    xml_path = request.form.get('xml_path')
    if not xml_path:
        return jsonify({"error": "XML path missing. Save XML first."}), 400
    xml_path = os.path.abspath(xml_path)
    if not os.path.exists(xml_path):
        return jsonify({"error": f"XML path not found: {xml_path}"}), 400
    # Skip schema validation: format differs from CORE XML
    run_id = str(uuid.uuid4())
    out_dir = os.path.dirname(xml_path)
    log_path = os.path.join(out_dir, f'cli-{run_id}.log')
    env = os.environ.copy(); env["PYTHONUNBUFFERED"] = "1"
    # Redirect output directly to log file for easy tailing
    log_f = open(log_path, 'w', encoding='utf-8')
    app.logger.info("[async] Starting CLI; log: %s", log_path)
    # derive core host/port (best-effort) from synchronous parse
    core_host = '127.0.0.1'
    core_port = 50051
    try:
        payload = _parse_scenarios_xml(xml_path)
        ch = payload.get('core', {}).get('host') if isinstance(payload.get('core'), dict) else None
        cp = payload.get('core', {}).get('port') if isinstance(payload.get('core'), dict) else None
        if ch: core_host = str(ch)
        if cp: core_port = int(cp)
    except Exception:
        pass
    # Attempt pre-save of current CORE session xml (best-effort) using derived host/port
    pre_saved = None
    try:
        pre_dir = os.path.join(out_dir, 'core-pre')
        pre_saved = _grpc_save_current_session_xml(core_host, core_port, pre_dir)
    except Exception:
        pre_saved = None
    if pre_saved:
        app.logger.debug("[async] Pre-run session XML saved to %s", pre_saved)
    # Capture scenario names from the editor XML now (CORE post XML will not be parsable by our scenarios parser)
    scen_names = _scenario_names_from_xml(xml_path)
    repo_root = _get_repo_root()
    # Use package CLI module invocation
    proc = subprocess.Popen([
        'core-python', '-u', '-m', 'core_topo_gen.cli',
        '--xml', xml_path,
        '--host', core_host,
        '--port', str(core_port),
        '--verbose',
    ], cwd=repo_root, stdout=log_f, stderr=subprocess.STDOUT, env=env)
    RUNS[run_id] = {
        'proc': proc,
        'log_path': log_path,
        'xml_path': xml_path,
        'done': False,
        'returncode': None,
        'pre_xml_path': pre_saved,
        'repo_root': repo_root,
        'core_host': core_host,
        'core_port': core_port,
        'scenario_names': scen_names,
        'post_xml_path': None,
    }
    return jsonify({"run_id": run_id})


@app.route('/run_status/<run_id>', methods=['GET'])
def run_status(run_id: str):
    meta = RUNS.get(run_id)
    if not meta:
        return jsonify({"error": "not found"}), 404
    proc = meta.get('proc')
    if proc and meta.get('returncode') is None:
        rc = proc.poll()
        if rc is not None:
            meta['done'] = True
            meta['returncode'] = rc
            # On successful completion (rc==0) append history once
            if rc == 0:
                try:
                    xml_path_local = meta.get('xml_path')
                    # Parse report path from log contents; fallback to latest under reports/
                    report_md = None
                    try:
                        lp = meta.get('log_path')
                        if lp and os.path.exists(lp):
                            with open(lp, 'r', encoding='utf-8', errors='ignore') as f:
                                txt = f.read()
                            report_md = _extract_report_path_from_text(txt)
                    except Exception:
                        report_md = None
                    if not report_md:
                        report_md = _find_latest_report_path()
                    if report_md:
                        app.logger.info("[async] Detected report path: %s", report_md)
                    # Best-effort: capture post-run CORE session XML
                    post_saved = None
                    try:
                        out_dir = os.path.dirname(xml_path_local or '')
                        post_dir = os.path.join(out_dir, 'core-post') if out_dir else os.path.join('outputs', 'core-post')
                        # Parse session id from logs if available for precise save
                        sid = _extract_session_id_from_text(txt)
                        post_saved = _grpc_save_current_session_xml(meta.get('core_host') or CORE_HOST, int(meta.get('core_port') or CORE_PORT), post_dir, session_id=sid)
                    except Exception:
                        post_saved = None
                    if post_saved:
                        meta['post_xml_path'] = post_saved
                        app.logger.debug("[async] Post-run session XML saved to %s", post_saved)
                    # Build a Full Scenario bundle including scripts
                    full_bundle = _build_full_scenario_archive(os.path.dirname(xml_path_local or ''), xml_path_local, (report_md if (report_md and os.path.exists(report_md)) else None), meta.get('pre_xml_path'), post_saved, run_id=run_id)
                    _append_run_history({
                        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
                        'mode': 'async',
                        # Only record session xml if we actually pulled it via gRPC
                        'xml_path': post_saved if (post_saved and os.path.exists(post_saved)) else None,
                        'post_xml_path': post_saved if (post_saved and os.path.exists(post_saved)) else None,
                        'scenario_xml_path': xml_path_local,
                        'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
                        'pre_xml_path': meta.get('pre_xml_path'),
                        'full_scenario_path': full_bundle,
                        'returncode': rc,
                        'run_id': run_id,
                        'scenario_names': meta.get('scenario_names') or [],
                    })
                except Exception:
                    pass
    # Determine report path
    xml_path = meta.get('xml_path', '')
    out_dir = os.path.dirname(xml_path)
    # Determine report path (attempt to parse log each time so UI can link it without refresh)
    report_md = None
    try:
        lp = meta.get('log_path')
        if lp and os.path.exists(lp):
            with open(lp, 'r', encoding='utf-8', errors='ignore') as f:
                txt = f.read()
            report_md = _extract_report_path_from_text(txt)
    except Exception:
        report_md = None
    return jsonify({
        'done': bool(meta.get('done')),
        'returncode': meta.get('returncode'),
        'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
        'xml_path': (meta.get('post_xml_path') if meta.get('post_xml_path') and os.path.exists(meta.get('post_xml_path')) else None),
        'log_path': meta.get('log_path'),
        'scenario_xml_path': xml_path,
        'pre_xml_path': meta.get('pre_xml_path'),
        'full_scenario_path': (lambda p: p if (p and os.path.exists(p)) else None)(meta.get('full_scenario_path')),
    })


@app.route('/upload_base', methods=['POST'])
def upload_base():
    f = request.files.get('base_xml')
    if not f or f.filename == '':
        flash('No base scenario file selected.')
        return redirect(url_for('index'))
    filename = secure_filename(f.filename)
    base_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'base')
    os.makedirs(base_dir, exist_ok=True)
    unique = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    saved_path = os.path.join(base_dir, f"{unique}-{filename}")
    f.save(saved_path)
    ok, errs = _validate_core_xml(saved_path)
    payload = _default_scenarios_payload()
    payload['base_upload'] = { 'path': saved_path, 'valid': bool(ok) }
    if not ok:
        flash('Base scenario XML is INVALID. See details link for errors.')
    else:
        flash('Base scenario uploaded and validated.')
        try:
            # set the base scenario file path on the first scenario for convenience
            payload['scenarios'][0]['base']['filepath'] = saved_path
        except Exception:
            pass
    _attach_base_upload(payload)
    return render_template('index.html', payload=payload, logs=(errs if not ok else ''), xml_preview='')

@app.route('/remove_base', methods=['POST'])
def remove_base():
    """Clear the base scenario file reference from the first scenario."""
    try:
        payload = _default_scenarios_payload()
        # If scenarios_json posted, honor that to keep user edits
        data_str = request.form.get('scenarios_json')
        if data_str:
            try:
                data = json.loads(data_str)
                if isinstance(data, dict) and 'scenarios' in data:
                    payload['scenarios'] = data['scenarios']
            except Exception:
                pass
        # Clear the base filepath of first scenario
        try:
            if payload['scenarios'] and isinstance(payload['scenarios'][0], dict):
                payload['scenarios'][0].get('base', {}).update({'filepath': ''})
        except Exception:
            pass
        flash('Base scenario removed.')
        # Do not attach base upload (cleared)
        return render_template('index.html', payload=payload, logs='', xml_preview='')
    except Exception as e:
        flash(f'Failed to remove base: {e}')
        return redirect(url_for('index'))


@app.route('/base_details')
def base_details():
    xml_path = request.args.get('path')
    if not xml_path or not os.path.exists(xml_path):
        return "File not found", 404
    ok, errs = _validate_core_xml(xml_path)
    summary = _analyze_core_xml(xml_path) if ok else {'error': errs}
    return render_template('base_details.html', xml_path=xml_path, valid=ok, errors=errs, summary=summary)


@app.route('/test_core', methods=['POST'])
def test_core():
    try:
        data: Dict[str, Any] = {}
        if request.is_json:
            data = request.get_json(silent=True) or {}
        else:
            data = {"host": request.form.get('host'), "port": request.form.get('port')}
        host = (data.get('host') or CORE_HOST).strip()
        try:
            port = int(data.get('port') or os.environ.get('CORE_PORT', CORE_PORT))
        except Exception:
            return jsonify({"ok": False, "error": "Invalid port"}), 200
        # If inside container and user kept localhost, try environment override or host.docker.internal
        if host in ('localhost', '127.0.0.1'):
            env_host = os.environ.get('CORE_HOST')
            if env_host and env_host not in ('localhost', '127.0.0.1'):
                host = env_host
            else:
                try:
                    import socket as _s
                    _s.gethostbyname('host.docker.internal')
                    host = 'host.docker.internal'
                except Exception:
                    pass
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect((host, port))
            sock.close()
            return jsonify({"ok": True, "host": host, "port": port})
        except Exception as e:
            try:
                sock.close()
            except Exception:
                pass
            return jsonify({"ok": False, "error": str(e)}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200


@app.route('/stream/<run_id>')
def stream_logs(run_id: str):
    meta = RUNS.get(run_id)
    if not meta:
        return Response('event: error\ndata: not found\n\n', mimetype='text/event-stream')
    log_path = meta.get('log_path')

    def generate():
        # Tail the log file as it is written
        last_pos = 0
        while True:
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_pos)
                    chunk = f.read()
                    if chunk:
                        last_pos = f.tell()
                        # Split into lines to keep events reasonable
                        for line in chunk.splitlines():
                            yield f"data: {line}\n\n"
            except FileNotFoundError:
                pass
            # Check process status
            proc = meta.get('proc')
            rc = None
            if proc:
                rc = proc.poll()
                if rc is not None and meta.get('returncode') is None:
                    meta['returncode'] = rc
                    meta['done'] = True
            if meta.get('done'):
                # Signal end regardless; client will stop listening
                yield "event: end\ndata: done\n\n"
                break
            time.sleep(0.5)

    headers = {
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',  # for some proxies
        'Content-Type': 'text/event-stream',
        'Connection': 'keep-alive',
    }
    return Response(generate(), headers=headers)


@app.route('/cancel_run/<run_id>', methods=['POST'])
def cancel_run(run_id: str):
    meta = RUNS.get(run_id)
    if not meta:
        return jsonify({"error": "not found"}), 404
    proc = meta.get('proc')
    try:
        if proc and proc.poll() is None:
            # Append a cancel marker to log, then terminate
            lp = meta.get('log_path')
            try:
                with open(lp, 'a', encoding='utf-8') as f:
                    f.write("\n== Run cancelled by user ==\n")
            except Exception:
                pass
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        meta['done'] = True
        if meta.get('returncode') is None:
            meta['returncode'] = -1
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- Data Sources -----------------
@app.route('/data_sources')
def data_sources_page():
    state = _load_data_sources_state()
    return render_template('data_sources.html', sources=state.get('sources', []))

@app.route('/data_sources/upload', methods=['POST'])
def data_sources_upload():
    f = request.files.get('csv_file')
    if not f or f.filename == '':
        flash('No file selected.')
        return redirect(url_for('data_sources_page'))
    filename = secure_filename(f.filename)
    if not filename.lower().endswith('.csv'):
        flash('Only .csv allowed.')
        return redirect(url_for('data_sources_page'))
    unique = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    dest_dir = os.path.join(DATA_SOURCES_DIR)
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, f"{unique}-{filename}")
    f.save(path)
    ok, note, norm_rows, skipped = _validate_and_normalize_data_source_csv(path, skip_invalid=True)
    if not ok:
        try: os.remove(path)
        except Exception: pass
        flash(f'Invalid CSV: {note}')
        return redirect(url_for('data_sources_page'))
    # Write back normalized CSV to ensure required/optional columns are present
    try:
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            for r in norm_rows:
                w.writerow(r)
        os.replace(tmp, path)
    except Exception:
        pass
    state = _load_data_sources_state()
    entry = {
        "id": uuid.uuid4().hex[:12],
        "name": filename,
        "path": path,
        "enabled": True,
        "rows": note,
        "uploaded": datetime.datetime.utcnow().isoformat() + 'Z'
    }
    state['sources'].append(entry)
    _save_data_sources_state(state)
    if ok and skipped:
        flash(f'CSV imported with {len(skipped)} invalid row(s) skipped.')
    else:
        flash('CSV imported.')
    return redirect(url_for('data_sources_page'))

@app.route('/data_sources/toggle/<sid>', methods=['POST'])
def data_sources_toggle(sid):
    state = _load_data_sources_state()
    for s in state.get('sources', []):
        if s.get('id') == sid:
            s['enabled'] = not s.get('enabled', False)
            break
    _save_data_sources_state(state)
    return redirect(url_for('data_sources_page'))

@app.route('/data_sources/delete/<sid>', methods=['POST'])
def data_sources_delete(sid):
    state = _load_data_sources_state()
    new_sources = []
    for s in state.get('sources', []):
        if s.get('id') == sid:
            try:
                if os.path.exists(s.get('path','')):
                    os.remove(s['path'])
            except Exception:
                pass
            continue
        new_sources.append(s)
    state['sources'] = new_sources
    _save_data_sources_state(state)
    flash('Deleted.')
    return redirect(url_for('data_sources_page'))

@app.route('/data_sources/refresh/<sid>', methods=['POST'])
def data_sources_refresh(sid):
    state = _load_data_sources_state()
    for s in state.get('sources', []):
        if s.get('id') == sid:
            ok, note, norm_rows, skipped = _validate_and_normalize_data_source_csv(s.get('path',''), skip_invalid=True)
            if ok and norm_rows:
                # Write back normalized CSV
                try:
                    p = s.get('path','')
                    tmp = p + '.tmp'
                    with open(tmp, 'w', encoding='utf-8', newline='') as f:
                        w = csv.writer(f)
                        for r in norm_rows:
                            w.writerow(r)
                    os.replace(tmp, p)
                except Exception:
                    pass
            if ok and skipped:
                note = note + f" (skipped {len(skipped)} invalid)"
            s['rows'] = note if ok else f"ERR: {note}"
            break
    _save_data_sources_state(state)
    return redirect(url_for('data_sources_page'))

@app.route('/data_sources/download/<sid>')
def data_sources_download(sid):
    state = _load_data_sources_state()
    for s in state.get('sources', []):
        if s.get('id') == sid and os.path.exists(s.get('path','')):
            return send_file(s['path'], as_attachment=True, download_name=os.path.basename(s['name']))
    flash('Not found')
    return redirect(url_for('data_sources_page'))

@app.route('/data_sources/export_all')
def data_sources_export_all():
    import io, zipfile
    state = _load_data_sources_state()
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        for s in state.get('sources', []):
            p = s.get('path')
            if p and os.path.exists(p):
                z.write(p, arcname=os.path.basename(p))
    mem.seek(0)
    return send_file(mem, as_attachment=True, download_name='data_sources.zip')

@app.route('/vuln_catalog')
def vuln_catalog():
    """Return vulnerability catalog built from enabled data source CSVs.

    Response JSON:
      {
        "types": [str],
        "vectors": [str],
        "items": [ {"Name","Path","Type","Startup","Vector","CVE","Description","References"} ]
      }
    Only includes rows from enabled data sources that validate.
    """
    try:
        state = _load_data_sources_state()
        types = set()
        vectors = set()
        items = []
        for s in state.get('sources', []):
            if not s.get('enabled'): continue
            p = s.get('path')
            if not p or not os.path.exists(p): continue
            ok, note, norm_rows, _skipped = _validate_and_normalize_data_source_csv(p, skip_invalid=True)
            if not ok or not norm_rows or len(norm_rows) < 2: continue
            header = norm_rows[0]
            idx = {name: header.index(name) for name in header if name in header}
            for r in norm_rows[1:]:
                try:
                    rec = {
                        'Name': r[idx.get('Name')],
                        'Path': r[idx.get('Path')],
                        'Type': r[idx.get('Type')],
                        'Startup': r[idx.get('Startup')],
                        'Vector': r[idx.get('Vector')],
                        'CVE': r[idx.get('CVE')] if 'CVE' in idx else 'n/a',
                        'Description': r[idx.get('Description')] if 'Description' in idx else 'n/a',
                        'References': r[idx.get('References')] if 'References' in idx else 'n/a',
                    }
                    # keep only non-empty mandatory values
                    if not rec['Name'] or not rec['Path']:
                        continue
                    items.append(rec)
                    if rec['Type']: types.add(rec['Type'])
                    if rec['Vector']: vectors.add(rec['Vector'])
                except Exception:
                    continue
        return jsonify({
            'types': sorted(types),
            'vectors': sorted(vectors),
            'items': items,
        })
    except Exception as e:
        return jsonify({'error': str(e), 'types': [], 'vectors': [], 'items': []}), 500


# ------------ Vulnerability compose helpers (GitHub-aware) ---------------
def _safe_name(s: str) -> str:
    try:
        return re.sub(r"[^a-z0-9_.-]+", "-", (s or '').strip().lower())[:80] or 'vuln'
    except Exception:
        return 'vuln'


def _parse_github_url(url: str):
    """Parse a GitHub URL. Supports formats:
    - https://github.com/owner/repo/tree/<branch>/<subpath>
    - https://github.com/owner/repo/blob/<branch>/<file_or_subpath>
    - https://github.com/owner/repo (no branch; default branch)

    Returns dict with keys:
      { 'is_github': bool, 'git_url': str|None, 'branch': str|None, 'subpath': str|None, 'mode': 'tree'|'blob'|'root' }
    """
    try:
        from urllib.parse import urlparse
        u = urlparse(url)
        if u.netloc.lower() != 'github.com':
            return {'is_github': False}
        parts = [p for p in u.path.strip('/').split('/') if p]
        if len(parts) < 2:
            return {'is_github': False}
        owner, repo = parts[0], parts[1]
        git_url = f"https://github.com/{owner}/{repo}.git"
        if len(parts) == 2:
            return {'is_github': True, 'git_url': git_url, 'branch': None, 'subpath': '', 'mode': 'root'}
        mode = parts[2]
        if mode not in ('tree', 'blob') or len(parts) < 4:
            # Unknown path mode; treat as root
            return {'is_github': True, 'git_url': git_url, 'branch': None, 'subpath': '', 'mode': 'root'}
        branch = parts[3]
        rest = '/'.join(parts[4:])
        return {'is_github': True, 'git_url': git_url, 'branch': branch, 'subpath': rest, 'mode': mode}
    except Exception:
        return {'is_github': False}


def _compose_candidates(base_dir: str):
    """Return possible compose file paths under base_dir in priority order."""
    cands = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']
    out = []
    try:
        for name in cands:
            p = os.path.join(base_dir, name)
            if os.path.exists(p):
                out.append(p)
    except Exception:
        pass
    return out

@app.route('/vuln_compose/status', methods=['POST'])
def vuln_compose_status():
    """Return status for a list of catalog items: whether compose file is downloaded and images pulled.

    Payload: { items: [{Name, Path}] }
    Returns: { items: [{Name, Path, exists: bool, pulled: bool, dir: str}] }
    """
    try:
        data = request.get_json(silent=True) or {}
        items = data.get('items') or []
        out = []
        base_out = os.path.abspath(_vuln_base_dir())
        os.makedirs(base_out, exist_ok=True)
        for it in items:
            name = (it.get('Name') or '').strip()
            path = (it.get('Path') or '').strip()
            compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
            safe = _safe_name(name or 'vuln')
            vdir = os.path.join(base_out, safe)
            gh = _parse_github_url(path)
            base_dir = vdir
            compose_file = None
            if gh.get('is_github'):
                repo_dir = os.path.join(vdir, _vuln_repo_subdir())
                sub = gh.get('subpath') or ''
                base_dir = os.path.join(repo_dir, sub) if sub else repo_dir
                exists = os.path.isdir(base_dir)
                # prefer provided compose name
                if exists and compose_name:
                    p = os.path.join(base_dir, compose_name)
                    if os.path.exists(p):
                        compose_file = p
                if not compose_file:
                    # find compose candidates within base_dir
                    cand = _compose_candidates(base_dir)
                    compose_file = cand[0] if cand else None
            else:
                # legacy direct download to vdir/docker-compose.yml
                compose_file = os.path.join(vdir, compose_name or 'docker-compose.yml')
                exists = os.path.exists(compose_file)
            pulled = False
            if exists and compose_file and shutil.which('docker'):
                try:
                    proc = subprocess.run(['docker', 'compose', '-f', compose_file, 'config', '--images'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
                    if proc.returncode == 0:
                        images = [ln.strip() for ln in (proc.stdout or '').splitlines() if ln.strip()]
                        if images:
                            present = []
                            for img in images:
                                p2 = subprocess.run(['docker', 'image', 'inspect', img], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                present.append(p2.returncode == 0)
                            pulled = all(present)
                except Exception:
                    pulled = False
            out.append({'Name': name, 'Path': path, 'compose': compose_name, 'compose_path': compose_file, 'exists': bool(exists), 'pulled': bool(pulled), 'dir': base_dir})
        return jsonify({'items': out})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/vuln_compose/download', methods=['POST'])
def vuln_compose_download():
    """Download docker-compose.yml for the given catalog items.

    Payload: { items: [{Name, Path}] }
    Returns: { items: [{Name, Path, ok: bool, dir: str, message: str}] }
    """
    try:
        from core_topo_gen.utils.vuln_process import _github_tree_to_raw as _to_raw
        data = request.get_json(silent=True) or {}
        items = data.get('items') or []
        out = []
        base_out = os.path.abspath(_vuln_base_dir())
        os.makedirs(base_out, exist_ok=True)
        import urllib.request
        for it in items:
            name = (it.get('Name') or '').strip()
            path = (it.get('Path') or '').strip()
            compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
            safe = _safe_name(name or 'vuln')
            vdir = os.path.join(base_out, safe)
            os.makedirs(vdir, exist_ok=True)
            gh = _parse_github_url(path)
            if gh.get('is_github'):
                # Clone the repo; use branch if provided
                if not shutil.which('git'):
                    out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': 'git not available'})
                    continue
                repo_dir = os.path.join(vdir, _vuln_repo_subdir())
                # If already cloned and looks valid, skip re-clone
                if os.path.isdir(os.path.join(repo_dir, '.git')):
                    out.append({'Name': name, 'Path': path, 'ok': True, 'dir': (os.path.join(repo_dir, gh.get('subpath') or '') if gh.get('subpath') else repo_dir), 'message': 'already downloaded'})
                    continue
                # Ensure empty directory
                try:
                    if os.path.exists(repo_dir):
                        shutil.rmtree(repo_dir)
                except Exception:
                    pass
                cmd = ['git', 'clone', '--depth', '1']
                if gh.get('branch'):
                    cmd += ['--branch', gh.get('branch')]
                cmd += [gh.get('git_url'), repo_dir]
                try:
                    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
                    if proc.returncode == 0 and os.path.isdir(repo_dir):
                        base_dir = os.path.join(repo_dir, gh.get('subpath') or '') if gh.get('subpath') else repo_dir
                        out.append({'Name': name, 'Path': path, 'ok': True, 'dir': base_dir, 'message': 'downloaded'})
                    else:
                        msg = (proc.stdout or '').strip()
                        out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': msg[-1000:] if msg else 'git clone failed'})
                except Exception as e:
                    out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': str(e)})
            else:
                # Legacy: direct download of compose file (use provided compose name)
                raw = _to_raw(path, compose_name) or (path.rstrip('/') + '/' + compose_name)
                yml_path = os.path.join(vdir, compose_name)
                try:
                    with urllib.request.urlopen(raw, timeout=30) as resp:
                        data_bin = resp.read(1_000_000)
                    with open(yml_path, 'wb') as f:
                        f.write(data_bin)
                    out.append({'Name': name, 'Path': path, 'ok': True, 'dir': vdir, 'message': 'downloaded', 'compose': compose_name})
                except Exception as e:
                    out.append({'Name': name, 'Path': path, 'ok': False, 'dir': vdir, 'message': str(e), 'compose': compose_name})
        return jsonify({'items': out})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/vuln_compose/pull', methods=['POST'])
def vuln_compose_pull():
    """Run docker compose pull for the given catalog items (assumes docker-compose.yml is present).

    Payload: { items: [{Name, Path}] }
    Returns: { items: [{Name, Path, ok: bool, message: str}] }
    """
    try:
        data = request.get_json(silent=True) or {}
        items = data.get('items') or []
        out = []
        base_out = os.path.abspath(_vuln_base_dir())
        for it in items:
            name = (it.get('Name') or '').strip()
            path = (it.get('Path') or '').strip()
            compose_name = (it.get('compose') or 'docker-compose.yml').strip() or 'docker-compose.yml'
            safe = _safe_name(name or 'vuln')
            vdir = os.path.join(base_out, safe)
            gh = _parse_github_url(path)
            if gh.get('is_github'):
                repo_dir = os.path.join(vdir, _vuln_repo_subdir())
                base_dir = os.path.join(repo_dir, gh.get('subpath') or '') if gh.get('subpath') else repo_dir
                # prefer provided compose name
                yml_path = os.path.join(base_dir, compose_name)
                if not os.path.exists(yml_path):
                    cand = _compose_candidates(base_dir)
                    yml_path = cand[0] if cand else None
            else:
                yml_path = os.path.join(vdir, compose_name)
            if not yml_path or not os.path.exists(yml_path):
                out.append({'Name': name, 'Path': path, 'ok': False, 'message': 'compose file missing', 'compose': compose_name})
                continue
            if not shutil.which('docker'):
                out.append({'Name': name, 'Path': path, 'ok': False, 'message': 'docker not available', 'compose': compose_name})
                continue
            try:
                proc = subprocess.run(['docker', 'compose', '-f', yml_path, 'pull'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                ok = proc.returncode == 0
                msg = 'ok' if ok else ((proc.stdout or '')[-1000:] if proc.stdout else 'failed')
                out.append({'Name': name, 'Path': path, 'ok': ok, 'message': msg, 'compose': compose_name})
            except Exception as e:
                out.append({'Name': name, 'Path': path, 'ok': False, 'message': str(e), 'compose': compose_name})
        return jsonify({'items': out})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/data_sources/edit/<sid>')
def data_sources_edit(sid):
    """Render an editable view of the CSV source in a simple table.
    """
    state = _load_data_sources_state()
    target = None
    for s in state.get('sources', []):
        if s.get('id') == sid:
            target = s
            break
    if not target:
        flash('Source not found')
        return redirect(url_for('data_sources_page'))
    path = target.get('path')
    if not path or not os.path.exists(path):
        flash('File missing')
        return redirect(url_for('data_sources_page'))
    # Read CSV safely
    rows = []
    with open(path, 'r', encoding='utf-8', errors='replace', newline='') as f:
        rdr = csv.reader(f)
        for r in rdr:
            rows.append(r)
    name = target.get('name') or os.path.basename(path)
    return render_template('data_source_edit.html', sid=sid, name=name, path=path, rows=rows)

@app.route('/data_sources/save/<sid>', methods=['POST'])
def data_sources_save(sid):
    """Save edited CSV content coming from the editor page.
    Expects JSON payload: { rows: string[][] }
    """
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or 'rows' not in data:
            return jsonify({"ok": False, "error": "Invalid payload"}), 400
        rows = data.get('rows')
        if not isinstance(rows, list) or any(not isinstance(r, list) for r in rows):
            return jsonify({"ok": False, "error": "Rows must be a list of lists"}), 400
        # Basic row length normalization (pad shorter rows to header length)
        maxw = max((len(r) for r in rows), default=0)
        norm = []
        for r in rows:
            if len(r) < maxw:
                r = r + [''] * (maxw - len(r))
            norm.append([str(c) if c is not None else '' for c in r])
        state = _load_data_sources_state()
        target = None
        for s in state.get('sources', []):
            if s.get('id') == sid:
                target = s
                break
        if not target:
            return jsonify({"ok": False, "error": "Source not found"}), 404
        path = target.get('path')
        if not path:
            return jsonify({"ok": False, "error": "Missing file path"}), 400
        # Validate and normalize according to schema
        # Write temp to validate with the same function used for uploads
        tmp_preview = path + '.editpreview'
        try:
            with open(tmp_preview, 'w', encoding='utf-8', newline='') as f:
                w = csv.writer(f)
                for r in norm:
                    w.writerow(r)
            ok2, note2, norm_rows2, skipped2 = _validate_and_normalize_data_source_csv(tmp_preview, skip_invalid=True)
        finally:
            try: os.remove(tmp_preview)
            except Exception: pass
        if not ok2:
            return jsonify({"ok": False, "error": note2}), 200
        # Atomic write normalized rows
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            for r in (norm_rows2 or norm):
                w.writerow(r)
        os.replace(tmp, path)
        # Update state row count
        ok, note = _validate_csv(path)
        if ok2 and skipped2:
            note_extra = f" (skipped {len(skipped2)} invalid)"
        else:
            note_extra = ''
        target['rows'] = (note if ok else f"ERR: {note}") + note_extra
        _save_data_sources_state(state)
        return jsonify({"ok": True, "skipped": len(skipped2) if ok2 else 0})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

def _purge_run_history_for_scenario(scenario_name: str, delete_artifacts: bool = True) -> int:
    """Remove any run history entries whose scenario_names contains scenario_name.
    Optionally delete associated artifact files (xml/report/pre-session xml) under outputs/.
    Returns number of entries removed.
    """
    try:
        if not os.path.exists(RUN_HISTORY_PATH):
            return 0
        with open(RUN_HISTORY_PATH, 'r', encoding='utf-8') as f:
            hist = json.load(f)
        if not isinstance(hist, list):
            return 0
        kept = []
        removed = 0
        for entry in hist:
            scen_list = []
            try:
                if 'scenario_names' in entry:
                    scen_list = entry.get('scenario_names') or []
                else:
                    scen_list = _scenario_names_from_xml(entry.get('xml_path'))
            except Exception:
                scen_list = []
            if scenario_name in scen_list:
                removed += 1
                if delete_artifacts:
                    for key in ('xml_path','report_path','pre_xml_path','post_xml_path','scenario_xml_path'):
                        p = entry.get(key)
                        if p and isinstance(p,str) and os.path.exists(p):
                            # Only delete if inside outputs directory for safety
                            try:
                                out_abs = os.path.abspath('outputs')
                                p_abs = os.path.abspath(p)
                                if p_abs.startswith(out_abs):
                                    try: os.remove(p_abs)
                                    except Exception: pass
                                    # Attempt to remove directory if empty afterwards
                                    try:
                                        parent = os.path.dirname(p_abs)
                                        if parent.startswith(out_abs) and os.path.isdir(parent) and not os.listdir(parent):
                                            os.rmdir(parent)
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                continue
            kept.append(entry)
        if removed:
            tmp = RUN_HISTORY_PATH + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(kept, f, indent=2)
            os.replace(tmp, RUN_HISTORY_PATH)
        return removed
    except Exception:
        return 0

@app.route('/purge_history_for_scenario', methods=['POST'])
def purge_history_for_scenario():
    try:
        data = request.get_json(silent=True) or {}
        name = (data.get('name') or '').strip()
        if not name:
            return jsonify({'removed': 0}), 200
        removed = _purge_run_history_for_scenario(name, delete_artifacts=True)
        return jsonify({'removed': removed})
    except Exception as e:
        return jsonify({'removed': 0, 'error': str(e)}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9090, debug=True)
