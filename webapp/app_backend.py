import os
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

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'xml'}

app = Flask(__name__)
app.secret_key = 'coretopogenweb'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# In-memory registry for async runs
RUNS: Dict[str, Dict[str, Any]] = {}

# Run history persistence (simple JSON log)
RUN_HISTORY_PATH = os.path.join('outputs', 'run_history.json')

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
        base = os.path.join(_get_repo_root(), 'reports')
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
        repo_root = _get_repo_root()
        report_dir = os.path.join(repo_root, 'reports')
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


def _grpc_save_current_session_xml(host: str, port: int, out_dir: str) -> str | None:
    """Attempt to connect to CORE daemon via gRPC and save the active session XML.

    This uses CoreGrpcClient.save_xml if available. If no active session exists
    or the gRPC client modules are unavailable, returns None silently.

    A timestamped filename core-session-<ts>.xml is written to out_dir.
    """
    try:
        from core.api.grpc.client import CoreGrpcClient  # type: ignore
    except Exception:
        return None
    address = f"{host}:{port}"
    ts = datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    os.makedirs(out_dir, exist_ok=True)
    # Pick first running/defined session if any; API lacks direct 'current' concept here.
    try:
        client = CoreGrpcClient(address=address)
        client.connect()
        try:
            sessions = client.get_sessions()
            if not sessions:
                return None
            # Prefer an started (state != DEFINITION) session; fall back to first
            target = None
            for s in sessions:
                # wrappers.SessionSummary likely has 'state' attr; safe getattr
                state = getattr(s, 'state', '').lower()
                if state and state != 'definition':
                    target = s; break
            if target is None:
                target = sessions[0]
            session_id = getattr(target, 'id', None) or getattr(target, 'session_id', None)
            if session_id is None:
                return None
            out_path = os.path.join(out_dir, f"core-session-{session_id}-{ts}.xml")
            try:
                client.save_xml(session_id=session_id, file_path=out_path)
            except Exception:
                return None
            finally:
                try:
                    client.close()
                except Exception:
                    pass
            if os.path.exists(out_path):
                return out_path
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
        # Pre-save any existing active CORE session XML (best-effort)
        try:
            pre_dir = os.path.join(os.path.dirname(xml_path), 'core-pre')
            pre_saved = _grpc_save_current_session_xml(CORE_HOST, CORE_PORT, pre_dir)
            if pre_saved:
                flash(f'Captured current CORE session XML: {os.path.basename(pre_saved)}')
        except Exception:
            pass
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
        # Report path (if generated by CLI): parse logs or fallback to latest under reports/
        report_md = _extract_report_path_from_text(logs) or _find_latest_report_path()
        # Read XML for preview
        xml_text = ""
        try:
            with open(xml_path, 'r', encoding='utf-8', errors='ignore') as f:
                xml_text = f.read()
        except Exception:
            xml_text = ""
        run_success = False
        if proc.returncode != 0:
            flash('CLI finished with errors. See logs.')
        else:
            run_success = True
            if report_md and os.path.exists(report_md):
                flash('CLI completed. Report ready to download.')
            else:
                flash('CLI completed. No report found.')
        payload = _parse_scenarios_xml(xml_path)
        if "core" not in payload:
            payload["core"] = _default_core_dict()
        _attach_base_upload(payload)
        # Always use absolute xml_path for result_path fallback
        payload["result_path"] = report_md if (report_md and os.path.exists(report_md)) else xml_path
        # Append run history entry on success
        if run_success:
            try:
                _append_run_history({
                    'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
                    'mode': 'sync',
                    'xml_path': xml_path,
                    'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
                    'pre_xml_path': pre_saved if 'pre_saved' in locals() else None,
                    'returncode': proc.returncode,
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
        return send_file(result_path, as_attachment=True)
    flash('Report not found.')
    return redirect(url_for('index'))

@app.route('/reports')
def reports_page():
    raw = _load_run_history()
    enriched = []
    for entry in raw:
        e = dict(entry)
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
    # Attempt pre-save of current CORE session xml (best-effort)
    pre_saved = None
    try:
        pre_dir = os.path.join(out_dir, 'core-pre')
        pre_saved = _grpc_save_current_session_xml(CORE_HOST, CORE_PORT, pre_dir)
    except Exception:
        pre_saved = None
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
                    _append_run_history({
                        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
                        'mode': 'async',
                        'xml_path': xml_path_local,
                        'report_path': report_md if (report_md and os.path.exists(report_md)) else None,
                        'pre_xml_path': meta.get('pre_xml_path'),
                        'returncode': rc,
                        'run_id': run_id,
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
        'xml_path': xml_path,
        'log_path': meta.get('log_path')
    ,'pre_xml_path': meta.get('pre_xml_path')
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
    ok, note = _validate_csv(path)
    if not ok:
        try: os.remove(path)
        except Exception: pass
        flash(f'Invalid CSV: {note}')
        return redirect(url_for('data_sources_page'))
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
            ok, note = _validate_csv(s.get('path',''))
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
                    for key in ('xml_path','report_path','pre_xml_path'):
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
