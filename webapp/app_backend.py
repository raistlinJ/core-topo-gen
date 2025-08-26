import os
import io
import json
import datetime
import time
import uuid
from typing import Dict, Any
import subprocess
import xml.etree.ElementTree as ET
from lxml import etree as LET  # XML validation
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, Response, jsonify
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'xml'}

app = Flask(__name__)
app.secret_key = 'coretopogenweb'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# In-memory registry for async runs
RUNS: Dict[str, Dict[str, Any]] = {}

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
    return {"scenarios": [scen], "result_path": None, "core": {"host": "localhost", "port": 50051}}


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
        repo_root = os.path.abspath('..')
        xsd_path = os.path.join(repo_root, 'validation', 'core-xml-syntax', 'corexml_codebased.xsd')
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
    payload['base_upload'] = None
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
            payload["core"] = {"host": "localhost", "port": 50051}
        payload["result_path"] = filepath
        payload['base_upload'] = None
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
        return render_template('index.html', payload={"scenarios": data.get("scenarios", []), "result_path": out_path, "core": {"host": "localhost", "port": 50051}, "base_upload": None}, logs="", xml_preview=xml_text)
    except Exception as e:
        flash(f'Failed to save XML: {e}')
        return redirect(url_for('index'))


@app.route('/run_cli', methods=['POST'])
def run_cli():
    xml_path = request.form.get('xml_path')
    if not xml_path or not os.path.exists(xml_path):
        flash('XML path missing or not found. Save XML first.')
        return redirect(url_for('index'))
    # Validate XML before running
    ok, errs = _validate_core_xml(xml_path)
    if not ok:
        flash('XML validation failed. Fix errors and try again.')
        # Read XML for preview
        xml_text = ''
        try:
            with open(xml_path, 'r', encoding='utf-8', errors='ignore') as f:
                xml_text = f.read()
        except Exception:
            pass
        payload = _parse_scenarios_xml(xml_path)
        if "core" not in payload:
            payload["core"] = {"host": "localhost", "port": 50051}
        # surface validation errors in logs area
        logs = f"INVALID\n{errs}"
        return render_template('index.html', payload=payload, logs=logs, xml_preview=xml_text)
    # Run core_topo_gen CLI
    try:
        proc = subprocess.run([
            'python', '-m', 'core_topo_gen.cli',
            '--xml', xml_path,
            '--verbose',
        ], cwd=os.path.abspath('..'), check=False, capture_output=True, text=True)
        logs = (proc.stdout or '') + ('\n' + proc.stderr if proc.stderr else '')
        # Report path (if generated by CLI)
        out_dir = os.path.dirname(xml_path)
        report_md = os.path.join(out_dir, 'report.md')
        # Read XML for preview
        xml_text = ""
        try:
            with open(xml_path, 'r', encoding='utf-8', errors='ignore') as f:
                xml_text = f.read()
        except Exception:
            xml_text = ""
        if proc.returncode != 0:
            flash('CLI finished with errors. See logs.')
        elif os.path.exists(report_md):
            flash('CLI completed. Report ready to download.')
        else:
            flash('CLI completed. No report found.')
        payload = _parse_scenarios_xml(xml_path)
        if "core" not in payload:
            payload["core"] = {"host": "localhost", "port": 50051}
        payload['base_upload'] = None
        payload["result_path"] = report_md if os.path.exists(report_md) else xml_path
        return render_template('index.html', payload=payload, logs=logs, xml_preview=xml_text)
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


@app.route('/run_cli_async', methods=['POST'])
def run_cli_async():
    xml_path = request.form.get('xml_path')
    if not xml_path or not os.path.exists(xml_path):
        return jsonify({"error": "XML path missing or not found. Save XML first."}), 400
    # Validate XML before running
    ok, errs = _validate_core_xml(xml_path)
    if not ok:
        return jsonify({"error": "XML validation failed.", "details": errs}), 400
    run_id = str(uuid.uuid4())
    out_dir = os.path.dirname(xml_path)
    log_path = os.path.join(out_dir, f'cli-{run_id}.log')
    env = os.environ.copy(); env["PYTHONUNBUFFERED"] = "1"
    # Redirect output directly to log file for easy tailing
    log_f = open(log_path, 'w', encoding='utf-8')
    proc = subprocess.Popen([
        'python', '-u', '-m', 'core_topo_gen.cli',
        '--xml', xml_path,
        '--verbose',
    ], cwd=os.path.abspath('..'), stdout=log_f, stderr=subprocess.STDOUT, env=env)
    RUNS[run_id] = {
        'proc': proc,
        'log_path': log_path,
        'xml_path': xml_path,
        'done': False,
        'returncode': None,
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
    # Determine report path
    xml_path = meta.get('xml_path', '')
    out_dir = os.path.dirname(xml_path)
    report_md = os.path.join(out_dir, 'report.md')
    return jsonify({
        'done': bool(meta.get('done')),
        'returncode': meta.get('returncode'),
        'report_path': report_md if os.path.exists(report_md) else None,
        'xml_path': xml_path,
        'log_path': meta.get('log_path')
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
    return render_template('index.html', payload=payload, logs=(errs if not ok else ''), xml_preview='')


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
        host = (data.get('host') or 'localhost').strip()
        try:
            port = int(data.get('port') or 50051)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid port"}), 200
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect((host, port))
            sock.close()
            return jsonify({"ok": True})
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9090, debug=True)
