import os
import sys
import xml.etree.ElementTree as ET
import subprocess
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QGroupBox,
    QFileDialog, QTreeWidget, QTreeWidgetItem, QMessageBox, QHeaderView
)


class BaseScenarioWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        top_row = QHBoxLayout()
        label = QLabel("Base Scenario File:")
        self.file_input = QLineEdit()
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_file)
        validate_button = QPushButton("Validate")
        validate_button.clicked.connect(self.validate_file)
        self.analyze_button = QPushButton("Analyze")
        self.analyze_button.setEnabled(False)
        self.analyze_button.clicked.connect(self.analyze_file)

        top_row.addWidget(label)
        top_row.addWidget(self.file_input, 1)
        top_row.addWidget(browse_button)
        top_row.addWidget(validate_button)
        top_row.addWidget(self.analyze_button)

        self.analysis_group = QGroupBox("Analysis Results")
        ag_layout = QVBoxLayout()
        self.analysis_tree = QTreeWidget()
        self.analysis_tree.setHeaderLabels(["Item", "Value"])
        try:
            header = self.analysis_tree.header()
            header.setStretchLastSection(False)
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            self.analysis_tree.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        except Exception:
            pass
        ag_layout.addWidget(self.analysis_tree)
        self.analysis_group.setLayout(ag_layout)

        outer = QVBoxLayout()
        outer.addLayout(top_row)
        outer.addWidget(self.analysis_group, 1)
        self.setLayout(outer)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Scenario XML", "", "XML Files (*.xml);;All Files (*)"
        )
        if file_path:
            self.file_input.setText(file_path)

    def to_xml(self):
        elem = ET.Element("BaseScenario")
        elem.set("filepath", self.file_input.text())
        return elem

    def from_xml(self, elem):
        filepath = elem.get("filepath", "")
        self.file_input.setText(filepath)

    # The following functions mirror the logic from the original main.py
    def validate_file(self):
        path = self.file_input.text().strip()
        if not path:
            QMessageBox.warning(self, "No file selected", "Please choose a scenario XML file first.")
            return
        if not os.path.exists(path):
            QMessageBox.warning(self, "File not found", f"The selected file does not exist:\n{path}")
            return

        base_dir = os.path.dirname(os.path.abspath(__file__))
        # gui/widgets -> project root
        base_dir = os.path.abspath(os.path.join(base_dir, "..", ".."))
        validator = os.path.join(base_dir, "validation", "core-xml-syntax", "xml_validator.py")
        schema = os.path.join(base_dir, "validation", "core-xml-syntax", "corexml_codebased.xsd")

        if not os.path.exists(validator):
            QMessageBox.critical(self, "Missing validator", f"Could not find validator script:\n{validator}")
            return
        if not os.path.exists(schema):
            QMessageBox.critical(self, "Missing schema", f"Could not find schema file:\n{schema}")
            return

        try:
            proc = subprocess.run([sys.executable, validator, path, schema], capture_output=True, text=True, check=False)
            out = (proc.stdout or "").strip()
            err = (proc.stderr or "").strip()
            first = out.splitlines()[:1]
            if proc.returncode == 0 and first == ["VALID"]:
                QMessageBox.information(self, "Validation Passed", "The XML validates against the schema.")
                self.analyze_button.setEnabled(True)
            else:
                details = out if out else err
                if not details:
                    details = f"Exit code: {proc.returncode}"
                QMessageBox.critical(self, "Validation Failed", details)
        except Exception as e:
            QMessageBox.critical(self, "Validation Error", str(e))

    def analyze_file(self):
        path = self.file_input.text().strip()
        if not path:
            QMessageBox.warning(self, "No file selected", "Please choose a scenario XML file first.")
            return
        if not os.path.exists(path):
            QMessageBox.warning(self, "File not found", f"The selected file does not exist:\n{path}")
            return

        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except Exception as e:
            QMessageBox.critical(self, "XML Error", f"Could not parse XML:\n{e}")
            return

        def tname(el):
            return el.tag.split('}', 1)[-1].lower()

        def first(*vals):
            for v in vals:
                if v is not None and str(v).strip() != "":
                    return str(v).strip()
            return None

        def child_text_by_names(el, names):
            names_l = {n.lower() for n in names}
            for ch in el.iter():
                if tname(ch) in names_l:
                    if ch.text and ch.text.strip():
                        return ch.text.strip()
                    for k in ("id", "name", "node", "node_id", "nodeid", "uuid"):
                        v = ch.get(k)
                        if v:
                            return str(v).strip()
            return None

        def id_or_name(el):
            v = first(el.get("id"), el.get("name"), el.get("nodeid"), el.get("node_id"), el.get("uuid"))
            if v:
                return v
            return child_text_by_names(el, {"id", "name", "nodeid", "node_id", "uuid"})

        node_like = {"node","host","router","switch","pc","server","workstation","device","vertex"}
        nodes = {}
        for el in root.iter():
            if tname(el) in node_like:
                nid = id_or_name(el)
                if nid:
                    nodes[str(nid)] = el

        if not nodes:
            for el in root.iter():
                nid = id_or_name(el)
                if nid:
                    nodes.setdefault(str(nid), el)

        connections = []
        conn_like = {"link","connection","edge","net","interfacepair","wire","channel","connector"}
        for el in root.iter():
            if tname(el) in conn_like:
                a = first(el.get("node1"), el.get("node_1"), el.get("a"), el.get("src"), el.get("source"), el.get("from"))
                b = first(el.get("node2"), el.get("node_2"), el.get("b"), el.get("dst"), el.get("target"), el.get("to"))

                if not a or not b:
                    n1 = n2 = None
                    for ch in el:
                        ct = tname(ch)
                        if ct in {"node1","end1"}:
                            n1 = first(ch.get("id"), ch.get("name"), child_text_by_names(ch, {"id","name"}))
                        elif ct in {"node2","end2"}:
                            n2 = first(ch.get("id"), ch.get("name"), child_text_by_names(ch, {"id","name"}))
                    if n1 and n2:
                        a, b = n1, n2

                if not a or not b:
                    refs = []
                    for ch in el.iter():
                        ct = tname(ch)
                        for key in ("node","node_id","nodeid","id","name","src","dst","source","target","from","to"):
                            v = ch.get(key)
                            if v:
                                refs.append(str(v).strip()); break
                        else:
                            if ct in {"node","node_id","nodeid","id","name","src","dst","source","target","from","to"} and ch.text and ch.text.strip():
                                refs.append(ch.text.strip())
                        if len(refs) >= 2:
                            break
                    if len(refs) >= 2:
                        a, b = refs[0], refs[1]

                if a and b:
                    connections.append((str(a), str(b)))

        services = []
        for el in root.iter():
            if "service" in tname(el):
                name = first(el.get("name"), el.text.strip() if el.text else None, child_text_by_names(el, {"name"}))
                if name:
                    services.append(name)

        flows = []
        for el in root.iter():
            tt = tname(el)
            if "flow" in tt or "traffic" in tt:
                src = first(el.get("src"), el.get("source"), el.get("from"), child_text_by_names(el, {"src","source","from"}))
                dst = first(el.get("dst"), el.get("target"), el.get("to"), child_text_by_names(el, {"dst","target","to"}))
                desc = first(el.get("type"), el.get("protocol"), child_text_by_names(el, {"type","protocol"}), "")
                if src or dst or desc:
                    flows.append({"src": src, "dst": dst, "desc": desc})

        degrees = {nid: 0 for nid in nodes}
        for a, b in connections:
            if a in degrees: degrees[a] += 1
            if b in degrees: degrees[b] += 1
        non_connected = [nid for nid, d in degrees.items() if d == 0]

        self.analysis_tree.clear()
        root_item = QTreeWidgetItem(["Summary", ""]) 
        self.analysis_tree.addTopLevelItem(root_item)

        QTreeWidgetItem(root_item, ["Node count", str(len(nodes))])
        QTreeWidgetItem(root_item, ["Connection count", str(len(connections))])

        services_item = QTreeWidgetItem(root_item, ["Services used", str(len(set(services)))])
        for s in sorted(set(services)):
            QTreeWidgetItem(services_item, [s, ""]) 

        flows_item = QTreeWidgetItem(root_item, ["Traffic flows", str(len(flows))])
        for f in flows:
            label = f"{(f['src'] or '?')} -> {(f['dst'] or '?')}"
            QTreeWidgetItem(flows_item, [label, f.get('desc') or ""]) 

        nc_item = QTreeWidgetItem(root_item, ["Non-connected nodes", str(len(non_connected))])
        for nid in non_connected:
            QTreeWidgetItem(nc_item, [str(nid), ""]) 

        self.analysis_tree.expandAll()
        try:
            self.analysis_tree.resizeColumnToContents(0)
            header = self.analysis_tree.header()
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        except Exception:
            pass
