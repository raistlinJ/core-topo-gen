import sys
import os
import subprocess
import xml.etree.ElementTree as ET
import json

from PyQt6.QtCore import Qt, QPoint, QStandardPaths
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QComboBox, QDoubleSpinBox, QSpinBox, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, QGroupBox, QFileDialog, QScrollArea, QTreeWidget, QTreeWidgetItem, QMenu, QSplitter, QInputDialog, QLineEdit, QMessageBox, QMainWindow, QStackedWidget, QSizePolicy, QFrame, QLayout)


# ---------------------------
# Base Scenario (file + validate)
# ---------------------------


class BaseScenarioWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        # Top row with file, browse, validate, analyze
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

        # Analysis results tree
        self.analysis_group = QGroupBox("Analysis Results")
        ag_layout = QVBoxLayout()
        self.analysis_tree = QTreeWidget()
        self.analysis_tree.setHeaderLabels(["Item", "Value"])
        ag_layout.addWidget(self.analysis_tree)
        self.analysis_group.setLayout(ag_layout)

        # Outer layout
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

    def validate_file(self):
        path = self.file_input.text().strip()
        if not path:
            QMessageBox.warning(self, "No file selected", "Please choose a scenario XML file first.")
            return
        if not os.path.exists(path):
            QMessageBox.warning(self, "File not found", f"The selected file does not exist:\n{path}")
            return

        # validator and schema expected in project tree
        base_dir = os.path.dirname(os.path.abspath(__file__))
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
        """Heuristic analysis of the selected XML file."""
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

        
        # Collect nodes (robust, namespace-agnostic)
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
                    # also try common id/name attrs
                    for k in ("id", "name", "node", "node_id", "nodeid", "uuid"):
                        v = ch.get(k)
                        if v:
                            return str(v).strip()
            return None

        def id_or_name(el):
            # prefer explicit id, then name, then common variants or child elements
            v = first(el.get("id"), el.get("name"), el.get("nodeid"), el.get("node_id"), el.get("uuid"))
            if v:
                return v
            return child_text_by_names(el, {"id", "name", "nodeid", "node_id", "uuid"})

        node_like = {"node","host","router","switch","pc","server","workstation","device","vertex"}
        nodes = {}
        node_types = {}
        for el in root.iter():
            if tname(el) in node_like:
                nid = id_or_name(el)
                if nid:
                    nid_s = str(nid)
                    nodes[nid_s] = el
                    node_types[nid_s] = tname(el)

        # If still nothing, try a very generic search for elements that contain a child id/name
        if not nodes:
            for el in root.iter():
                nid = id_or_name(el)
                if nid:
                    nid_s = str(nid)
                    nodes.setdefault(nid_s, el)
                    node_types.setdefault(nid_s, tname(el))

        # Connections (support CORE-style <link><node1 id=../><node2 id=../></link> and many others)
        connections = []
        conn_like = {"link","connection","edge","net","interfacepair","wire","channel","connector"}
        for el in root.iter():
            if tname(el) in conn_like:
                # 1) attribute forms
                a = first(el.get("node1"), el.get("node_1"), el.get("a"),
                          el.get("src"), el.get("source"), el.get("from"))
                b = first(el.get("node2"), el.get("node_2"), el.get("b"),
                          el.get("dst"), el.get("target"), el.get("to"))

                # 2) CORE-style child tags: <node1 id="..."/>, <node2 id="..."/>
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

                # 3) generic nested references: any child with node-ish attributes or tags
                if not a or not b:
                    refs = []
                    for ch in el.iter():
                        ct = tname(ch)
                        # consider both attributes and element text
                        for key in ("node","node_id","nodeid","id","name","src","dst","source","target","from","to"):
                            v = ch.get(key)
                            if v:
                                refs.append(str(v).strip()); break
                        else:
                            # fallback to element text if tag name itself is a ref name
                            if ct in {"node","node_id","nodeid","id","name","src","dst","source","target","from","to"}:
                                if ch.text and ch.text.strip():
                                    refs.append(ch.text.strip())
                        if len(refs) >= 2:
                            break
                    if len(refs) >= 2:
                        a, b = refs[0], refs[1]

                if a and b:
                    connections.append((str(a), str(b)))

        # Services
        services = []
        for el in root.iter():
            if "service" in tname(el):
                name = first(el.get("name"), el.text.strip() if el.text else None, child_text_by_names(el, {"name"}))
                if name:
                    services.append(name)

        # Traffic flows
        flows = []
        for el in root.iter():
            tt = tname(el)
            if "flow" in tt or "traffic" in tt:
                src = first(el.get("src"), el.get("source"), el.get("from"),
                            child_text_by_names(el, {"src","source","from"}))
                dst = first(el.get("dst"), el.get("target"), el.get("to"),
                            child_text_by_names(el, {"dst","target","to"}))
                desc = first(el.get("type"), el.get("protocol"),
                             child_text_by_names(el, {"type","protocol"}), "")
                if src or dst or desc:
                    flows.append({"src": src, "dst": dst, "desc": desc})

        # Non-connected nodes
        degrees = {nid: 0 for nid in nodes}
        for a, b in connections:
            if a in degrees: degrees[a] += 1
            if b in degrees: degrees[b] += 1
        non_connected = [nid for nid, d in degrees.items() if d == 0]

        # Populate Analysis Results tree
# Populate Analysis Results tree
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
            label = f"{(f['src'] or '?')} Ã¢â€ ' {(f['dst'] or '?')}"
            QTreeWidgetItem(flows_item, [label, f.get('desc') or ""])

        nc_item = QTreeWidgetItem(root_item, ["Non-connected nodes", str(len(non_connected))])
        for nid in non_connected:
            QTreeWidgetItem(nc_item, [str(nid), ""])

        self.analysis_tree.expandAll()

class NotesWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout()
        label = QLabel("Description / Notes:")
        self.text = QTextEdit()
        self.text.setPlaceholderText("Enter scenario notes here...")
        self.text.setMinimumHeight(200)
        lay.addWidget(label)
        lay.addWidget(self.text, 1)
        self.setLayout(lay)

    def to_xml(self):
        section_elem = ET.Element("section", name="Notes")
        note_elem = ET.SubElement(section_elem, "notes")
        note_elem.text = self.text.toPlainText() or ""
        return section_elem

    def from_xml(self, section_elem):
        note_elem = section_elem.find("notes")
        self.text.setPlainText(note_elem.text if note_elem is not None and note_elem.text else "")


# ---------------------------
# Generic Section (with factors)
# ---------------------------

class SectionWidget(QWidget):
    """
    Generic section widget. Special-cases the Traffic section to avoid overlapping
    by placing each profile in a flat QGroupBox whose layout has a minimum-size
    constraint so it always grows to fit visible child controls.
    """
    def __init__(self, section_name, dropdown_items=None, parent=None):
        super().__init__(parent)
        self.max_rows = 10
        self.section_name = section_name
        self.dropdown_items = dropdown_items or ["Random", "Option 1", "Option 2", "Option 3"]

        # Set size policy to expand in both directions
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        # Per-section overrides
        if self.section_name == "Node Information":
            self.dropdown_items = ["Server", "Workstation", "PC", "Random"]
        elif self.section_name == "Routing":
            self.dropdown_items = ["RIP", "RIPv2", "BGP", "OSPFv2", "OSPFv3"]
        elif self.section_name == "Services":
            self.dropdown_items = ["SSH", "HTTP", "DHCPClient", "Random"]
        elif self.section_name == "Traffic":
            self.dropdown_items = ["Custom", "TCP", "UDP"]
        elif self.section_name == "Events":
            self.dropdown_items = ["Script Path"]
        elif self.section_name == "Vulnerabilities":
            self.dropdown_items = ["SSHCreds", "Bashbug", "FileArtifact", "Incompetence", "Random"]
        elif self.section_name == "Segmentation":
            self.dropdown_items = ["Firewall", "NAT", "VPN", "Random"]

        # Layout skeleton
        root_v = QVBoxLayout(self)
        root_v.setContentsMargins(0, 0, 0, 0)
        root_v.setSpacing(8)

        # Header row
        top_row = QHBoxLayout()
        top_row.addWidget(QLabel(section_name))
        self.add_dropdown_btn = QPushButton("Add Entry")
        if self.section_name == "Traffic":
            self.add_dropdown_btn.setText("Add traffic profile")
        elif self.section_name == "Segmentation":
            self.add_dropdown_btn.setText("Add segment type")
        elif self.section_name == "Node Information":
            self.add_dropdown_btn.setText("Add node type")
        elif self.section_name == "Routing":
            self.add_dropdown_btn.setText("Add protocol")
        elif self.section_name == "Services":
            self.add_dropdown_btn.setText("Add service")
        elif self.section_name == "Events":
            self.add_dropdown_btn.setText("Add event")
        self.add_dropdown_btn.clicked.connect(self.add_dropdown)
        top_row.addWidget(self.add_dropdown_btn)

        self.count_label = QLabel("")
        self.count_label.setStyleSheet("color:#666; margin-left:6px;")
        top_row.addWidget(self.count_label)
        top_row.addStretch(1)
        root_v.addLayout(top_row)

        # Optional spinners for nodes and density
        self.nodes_spin = None
        self.density_spin = None
        
        # Only add Total Nodes spinner for Node Information section
        if self.section_name == "Node Information":
            nodes_row = QHBoxLayout()
            nodes_row.addWidget(QLabel("Total Nodes:"))
            self.nodes_spin = QSpinBox()
            self.nodes_spin.setRange(1, 100)
            self.nodes_spin.setValue(1)
            nodes_row.addWidget(self.nodes_spin)
            root_v.addLayout(nodes_row)
        
        # Add density spin box for specified sections (including Segmentation)
        if self.section_name in ["Routing", "Services", "Traffic", "Events", "Vulnerabilities", "Segmentation"]:
            density_row = QHBoxLayout()
            density_row.addWidget(QLabel("Density:"))
            self.density_spin = QDoubleSpinBox()
            self.density_spin.setRange(0.0, 1.0)
            self.density_spin.setDecimals(3)
            self.density_spin.setSingleStep(0.01)
            self.density_spin.setValue(0.5)
            density_row.addWidget(self.density_spin)
            density_row.addStretch(1)
            root_v.addLayout(density_row)

        # Create container widget that will expand to fill available space
        self._dropdowns_container = QWidget()
        self._dropdowns_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        # Use a layout that expands properly
        self.dropdowns_layout = QVBoxLayout()
        self.dropdowns_layout.setContentsMargins(0, 0, 0, 0)
        self.dropdowns_layout.setSpacing(8)
        # Add stretch at the end to push content to top but allow expansion
        self.dropdowns_layout.addStretch(1)
        self._dropdowns_container.setLayout(self.dropdowns_layout)

        # Configure scroll area to expand properly
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._scroll.setWidget(self._dropdowns_container)
        
        # Add scroll area with stretch factor to fill remaining space
        root_v.addWidget(self._scroll, 1)

        # State
        self.dropdown_factor_pairs = []  # (combo, factor_spin, key, remove_button)
        self.traffic_extras = {}         # key -> (pattern_combo, rate_spin, period_spin, jitter_spin, group_box)

        self.warning_label = QLabel("")
        self.warning_label.setStyleSheet("color: red")
        root_v.addWidget(self.warning_label)

        # Start with one row
        self.add_dropdown()
        self.update_count_label()

    # ---- helpers ----
    def _apply_limits(self):
        at_max = len(self.dropdown_factor_pairs) >= self.max_rows
        self.warning_label.setText("Max reached" if at_max else "")
        self.add_dropdown_btn.setEnabled(not at_max)

    def _refresh_scroll(self):
        # force relayout/resize to avoid overlap when toggling visibility
        self._dropdowns_container.adjustSize()
        self._scroll.widget().adjustSize()
        self._scroll.ensureVisible(0, 0, 1, 1)

    def _remove_entry(self, key):
        # find tuple with key
        for entry in list(self.dropdown_factor_pairs):
            combo, spin, k, rm = entry[:4]  # Get first 4 elements
            if k is key:
                self.dropdown_factor_pairs.remove(entry)
                if self.section_name == "Traffic":
                    extra = self.traffic_extras.pop(k, None)
                    if extra and extra[-1] is not None:
                        box = extra[-1]
                        box.setParent(None)
                        box.deleteLater()
                else:
                    # key is a layout; remove its widgets
                    layout = k
                    while layout.count():
                        item = layout.takeAt(0)
                        w = item.widget()
                        if w:
                            w.setParent(None)
                            w.deleteLater()
                    # Remove from parent layout
                    self.dropdowns_layout.removeItem(layout)
                    layout.setParent(None)
                break
        self.redistribute_factors()
        self.update_count_label()
        self._apply_limits()
        self._refresh_scroll()

    # ---- public API ----
    def add_dropdown(self):
        if len(self.dropdown_factor_pairs) >= self.max_rows:
            self._apply_limits()
            return

        is_traffic = (self.section_name == "Traffic")

        # Main row for selection + factor + remove
        row = QHBoxLayout()
        row.setSpacing(8)
        combo = QComboBox()
        combo.addItems(self.dropdown_items)
        # default to "Random" when present
        idx = combo.findText("Random")
        if idx >= 0:
            combo.setCurrentIndex(idx)
        row.addWidget(combo)

        # For Events section, add script path field and browse button
        script_path_edit = None
        script_browse_btn = None
        if self.section_name == "Events":
            script_path_edit = QLineEdit()
            script_path_edit.setPlaceholderText("Enter script path...")
            script_browse_btn = QPushButton("Browse")
            script_browse_btn.setFixedWidth(70)
            
            def browse_script():
                file_path, _ = QFileDialog.getOpenFileName(
                    self, "Select Script File", "", "All Files (*)"
                )
                if file_path:
                    script_path_edit.setText(file_path)
            
            script_browse_btn.clicked.connect(browse_script)
            row.addWidget(script_path_edit, 1)
            row.addWidget(script_browse_btn)

        row.addWidget(QLabel("Weight:"))
        factor_spin = QDoubleSpinBox()
        factor_spin.setRange(0.0, 1.0)
        factor_spin.setDecimals(3)
        factor_spin.setSingleStep(0.05)
        factor_spin.valueChanged.connect(self.validate_factors)
        row.addWidget(factor_spin)

        remove_btn = QPushButton("Remove")
        remove_btn.setFixedWidth(70)
        row.addWidget(remove_btn)
        row.addStretch(1)

        if is_traffic:
            # Build grouped panel
            group_box = QGroupBox(f"Profile {len(self.traffic_extras) + 1}")
            group_box.setFlat(True)
            group_box.setStyleSheet(
                "QGroupBox { background: transparent; border: 1px solid rgba(0,0,0,40); margin-top: 12px; }"
                "QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }"
            )
            group_box.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            group_v = QVBoxLayout(group_box)
            group_v.setContentsMargins(8, 8, 8, 8)
            group_v.setSpacing(6)
            group_v.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)

            # Pattern row
            pattern_row = QHBoxLayout()
            pattern_row.setSpacing(8)
            pattern_row.addWidget(QLabel("Pattern:"))
            pattern_combo = QComboBox()
            pattern_combo.addItems(["1kbps", "5kbps", "Jitter", "Periodic (repeat every x seconds)", "Random", "Custom"])
            pattern_row.addWidget(pattern_combo)

            # Extra inputs
            extra_row = QHBoxLayout()
            extra_row.setSpacing(8)
            rate_label = QLabel("Rate (kbps):")
            rate_spin = QDoubleSpinBox(); rate_spin.setRange(0.1, 100000.0); rate_spin.setDecimals(1); rate_spin.setValue(64.0)
            period_label = QLabel("Period (s):")
            period_spin = QDoubleSpinBox(); period_spin.setRange(0.1, 3600.0); period_spin.setDecimals(1); period_spin.setValue(1.0)
            jitter_label = QLabel("Jitter (%):")
            jitter_spin = QDoubleSpinBox(); jitter_spin.setRange(0.0, 100.0); jitter_spin.setDecimals(1); jitter_spin.setValue(10.0)
            for w in (rate_label, rate_spin, period_label, period_spin, jitter_label, jitter_spin):
                extra_row.addWidget(w)

            def _apply_vis():
                s = pattern_combo.currentText()
                show_rate = (s == "Custom")
                show_period = s.startswith("Periodic")
                show_jitter = (s == "Jitter")
                rate_label.setVisible(show_rate); rate_spin.setVisible(show_rate)
                period_label.setVisible(show_period); period_spin.setVisible(show_period)
                jitter_label.setVisible(show_jitter); jitter_spin.setVisible(show_jitter)
                if s == "Periodic (1s)":
                    period_spin.setValue(1.0)
                elif s == "Periodic (5s)":
                    period_spin.setValue(5.0)
                group_box.adjustSize()
                group_box.updateGeometry()
                self._refresh_scroll()

            pattern_combo.currentTextChanged.connect(_apply_vis)
            _apply_vis()

            # Assemble
            group_v.addLayout(row)
            group_v.addLayout(pattern_row)
            group_v.addLayout(extra_row)
            
            # Insert before the stretch at the end
            self.dropdowns_layout.insertWidget(self.dropdowns_layout.count() - 1, group_box)

            key = group_box
            self.traffic_extras[key] = (pattern_combo, rate_spin, period_spin, jitter_spin, group_box)
            remove_btn.clicked.connect(lambda: self._remove_entry(key))
            self.dropdown_factor_pairs.append((combo, factor_spin, key, remove_btn))
        else:
            # Non-traffic: plain row
            # Insert before the stretch at the end
            self.dropdowns_layout.insertLayout(self.dropdowns_layout.count() - 1, row)
            key = row
            remove_btn.clicked.connect(lambda: self._remove_entry(key))
            # Store script path components for Events section
            if self.section_name == "Events":
                self.dropdown_factor_pairs.append((combo, factor_spin, key, remove_btn, script_path_edit, script_browse_btn))
            else:
                self.dropdown_factor_pairs.append((combo, factor_spin, key, remove_btn))

        self.redistribute_factors()
        self.update_count_label()
        self._apply_limits()
        self._refresh_scroll()

    def clear_all_rows(self):
        # remove all entries from container
        for entry in list(self.dropdown_factor_pairs):
            combo, spin, key = entry[:3]  # Get first 3 elements
            if self.section_name == "Traffic":
                extra = self.traffic_extras.pop(key, None)
                if extra and extra[-1] is not None:
                    box = extra[-1]
                    box.setParent(None)
                    box.deleteLater()
            else:
                layout = key
                while layout.count():
                    item = layout.takeAt(0)
                    w = item.widget()
                    if w: 
                        w.setParent(None)
                        w.deleteLater()
                self.dropdowns_layout.removeItem(layout)
                layout.setParent(None)
        self.dropdown_factor_pairs.clear()
        self._refresh_scroll()

    # ---- factor management ----
    def redistribute_factors(self):
        n = len(self.dropdown_factor_pairs)
        if n == 0:
            return
        even = round(1.0 / n, 3)
        # last spin takes the residual to ensure sum ~1.0
        for i, entry in enumerate(self.dropdown_factor_pairs):
            _, spin = entry[:2]  # Get first 2 elements (combo, factor_spin)
            if i < n - 1:
                spin.blockSignals(True); spin.setValue(even); spin.blockSignals(False)
            else:
                resid = max(0.0, 1.0 - sum(e[1].value() for e in self.dropdown_factor_pairs[:-1]))
                spin.blockSignals(True); spin.setValue(round(resid, 3)); spin.blockSignals(False)

    def validate_factors(self):
        s = round(sum(entry[1].value() for entry in self.dropdown_factor_pairs), 3)
        if abs(s - 1.0) > 0.005:
            self.warning_label.setText(f"Warning: weights sum to {s:.3f} (should be 1.000)")
        else:
            self.warning_label.setText("")

    def update_count_label(self):
        try:
            current = len(self.dropdown_factor_pairs)
            max_rows = getattr(self, 'max_rows', 10)
            if hasattr(self, 'count_label') and self.count_label is not None:
                self.count_label.setText(f"({current}/{max_rows})")
        except Exception:
            pass

    # ---- XML IO ----
    def to_xml(self):
        section_elem = ET.Element("section", name=self.section_name)
        if self.nodes_spin is not None:
            if self.section_name == "Node Information":
                section_elem.set("total_nodes", str(self.nodes_spin.value()))
        
        # Save density value for applicable sections
        if self.density_spin is not None:
            section_elem.set("density", f"{self.density_spin.value():.3f}")
            
        for entry in self.dropdown_factor_pairs:
            combo, factor, key = entry[:3]  # Get first 3 elements
            item_elem = ET.SubElement(section_elem, "item")
            item_elem.set("selected", combo.currentText())
            item_elem.set("factor", f"{factor.value():.3f}")
            
            # Handle Events section script path
            if self.section_name == "Events" and len(entry) >= 6:
                script_path_edit = entry[4]  # script_path_edit is 5th element (index 4)
                if script_path_edit and script_path_edit.text().strip():
                    item_elem.set("script_path", script_path_edit.text().strip())
                    
            if self.section_name == "Traffic" and key in self.traffic_extras:
                pattern_combo, rate_spin, period_spin, jitter_spin, _box = self.traffic_extras[key]
                sel = pattern_combo.currentText()
                item_elem.set("pattern", sel)
                # Save extra parameters
                item_elem.set("rate_kbps", f"{rate_spin.value():.1f}")
                item_elem.set("period_s", f"{period_spin.value():.1f}")
                item_elem.set("jitter_pct", f"{jitter_spin.value():.1f}")
        return section_elem

    def from_xml(self, section_elem):
        # optional totals
        if self.nodes_spin is not None:
            if self.section_name == "Node Information":
                v = section_elem.get("total_nodes")
                if v: self.nodes_spin.setValue(int(v))
        
        # Load density value for applicable sections
        if self.density_spin is not None:
            density_val = section_elem.get("density")
            if density_val:
                try:
                    self.density_spin.setValue(float(density_val))
                except Exception:
                    pass

        # rebuild rows
        self.clear_all_rows()
        items = section_elem.findall("item")
        if not items:
            self.add_dropdown()
            return

        for item_elem in items:
            self.add_dropdown()
            entry = self.dropdown_factor_pairs[-1]
            combo, factor, key = entry[:3]  # Get first 3 elements
            
            # selection
            sel = item_elem.get("selected", "Random")
            idx = combo.findText(sel)
            if idx >= 0:
                combo.setCurrentIndex(idx)
            # factor
            try:
                factor.setValue(float(item_elem.get("factor", "1.0")))
            except Exception:
                pass

            # Handle Events section script path
            if self.section_name == "Events" and len(entry) >= 6:
                script_path_edit = entry[4]  # script_path_edit is 5th element (index 4)
                script_path = item_elem.get("script_path", "")
                if script_path_edit and script_path:
                    script_path_edit.setText(script_path)

            if self.section_name == "Traffic" and key in self.traffic_extras:
                pattern_combo, rate_spin, period_spin, jitter_spin, box = self.traffic_extras[key]
                psel = item_elem.get("pattern", "Random")
                idxp = pattern_combo.findText(psel)
                if idxp >= 0:
                    pattern_combo.setCurrentIndex(idxp)
                # extra params
                try:
                    if item_elem.get("rate_kbps") is not None:
                        rate_spin.setValue(float(item_elem.get("rate_kbps")))
                    if item_elem.get("period_s") is not None:
                        period_spin.setValue(float(item_elem.get("period_s")))
                    if item_elem.get("jitter_pct") is not None:
                        jitter_spin.setValue(float(item_elem.get("jitter_pct")))
                except Exception:
                    pass

        self.validate_factors()
        self._refresh_scroll()

class ScenarioEditor(QWidget):
    def __init__(self):
        super().__init__()
        # Set size policy to expand in both directions
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.stacked = QStackedWidget()
        self.stacked.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.pages = {}
        self.sections = {}

        # Base Scenario page
        base_page = QWidget()
        base_page.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        base_v = QVBoxLayout(base_page)
        base_v.setContentsMargins(8, 8, 8, 8)
        self.base_scenario_group = QGroupBox("Base Scenario")
        self.base_scenario_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        base_layout = QVBoxLayout()
        self.base_scenario_widget = BaseScenarioWidget()
        base_layout.addWidget(self.base_scenario_widget)
        self.base_scenario_group.setLayout(base_layout)
        base_v.addWidget(self.base_scenario_group, 1)
        self.stacked.addWidget(base_page)
        self.pages["Base Scenario"] = base_page

        # Section pages
        for name in [
            "Node Information",
            "Routing",
            "Services",
            "Traffic",
            "Events",
            "Vulnerabilities",
            "Segmentation",
        ]:
            section = SectionWidget(name)
            self.sections[name] = section

            page = QWidget()
            page.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            pv = QVBoxLayout(page)
            pv.setContentsMargins(8, 8, 8, 8)
            group_box = QGroupBox(name)
            group_box.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
            group_layout = QVBoxLayout()
            group_layout.addWidget(section, 1)
            group_box.setLayout(group_layout)
            pv.addWidget(group_box, 1)
            page.setLayout(pv)

            self.stacked.addWidget(page)
            self.pages[name] = page

        # Notes page
        notes_page = QWidget()
        notes_page.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        notes_v = QVBoxLayout(notes_page)
        notes_v.setContentsMargins(8, 8, 8, 8)
        self.notes_widget = NotesWidget()
        notes_group = QGroupBox("Notes")
        notes_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        notes_layout = QVBoxLayout()
        notes_layout.addWidget(self.notes_widget, 1)
        notes_group.setLayout(notes_layout)
        notes_v.addWidget(notes_group, 1)
        self.stacked.addWidget(notes_page)
        self.pages["Notes"] = notes_page

        layout.addWidget(self.stacked, 1)

    def set_active_section(self, section_name: str | None):
        if not section_name or section_name not in self.pages:
            section_name = "Base Scenario"
        self.stacked.setCurrentWidget(self.pages[section_name])

    def to_xml(self):
        scenario_elem = ET.Element("ScenarioEditor")
        scenario_elem.append(self.base_scenario_widget.to_xml())
        for name, section in self.sections.items():
            scenario_elem.append(section.to_xml())
        scenario_elem.append(self.notes_widget.to_xml())
        return scenario_elem

    def from_xml(self, scenario_elem):
        base_elem = scenario_elem.find("BaseScenario")
        if base_elem is not None:
            self.base_scenario_widget.from_xml(base_elem)

        for section_elem in scenario_elem.findall("section"):
            name = section_elem.get("name", "")
            if name in self.sections:
                self.sections[name].from_xml(section_elem)
            elif name == "Notes":
                self.notes_widget.from_xml(section_elem)


# ---------------------------
# Main Window + Tree
# ---------------------------
SECTION_ORDER = [
    "Base Scenario",
    "Node Information",
    "Routing",
    "Services",
    "Traffic",
    "Events",
    "Vulnerabilities",
    "Segmentation",
    "Notes",
]

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Scenario Editor")

        self.current_item: QTreeWidgetItem | None = None
        self.current_editor: ScenarioEditor | None = None
        self.settings_file = self.get_settings_file_path()

        splitter = QSplitter(self)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Scenarios"])
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.open_context_menu)
        self.tree.itemClicked.connect(self.on_tree_click)

        self.right_panel = QWidget()
        self.right_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        right_layout = QVBoxLayout(self.right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        splitter.addWidget(self.tree)
        splitter.addWidget(self.right_panel)
        self.tree.setMinimumWidth(220)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        self.setCentralWidget(splitter)

        # File menu (basic Save/Load)
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        save_action = file_menu.addAction("Save…")
        save_action.triggered.connect(self.save_all)
        load_action = file_menu.addAction("Load…")
        load_action.triggered.connect(self.load_from_path)

        # Try to load last file or start with defaults
        self.load_last_file_or_defaults()

    def get_settings_file_path(self):
        """Get the path for storing application settings."""
        app_data_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation)
        if not os.path.exists(app_data_dir):
            os.makedirs(app_data_dir)
        return os.path.join(app_data_dir, "scenario_editor_settings.json")

    def save_settings(self, last_file_path=None):
        """Save application settings including last loaded file."""
        settings = {
            "last_file": last_file_path
        }
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save settings: {e}")

    def load_settings(self):
        """Load application settings."""
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load settings: {e}")
        return {}

    def load_last_file_or_defaults(self):
        """Load the last opened file, or start with defaults if file doesn't exist."""
        settings = self.load_settings()
        last_file = settings.get("last_file")
        
        if last_file and os.path.exists(last_file):
            try:
                self.load_scenarios_from_file(last_file)
                return
            except Exception as e:
                print(f"Warning: Could not load last file {last_file}: {e}")
        
        # Fall back to default scenario
        self.add_scenario("Scenario 1")

    # ---- Tree helpers ----
    def add_scenario(self, name: str):
        item = QTreeWidgetItem([name])
        self.tree.addTopLevelItem(item)
        for sec in SECTION_ORDER[1:]:
            child = QTreeWidgetItem([sec])
            item.addChild(child)
        item.setExpanded(True)
        self.build_editor_for_item(item)

    def build_editor_for_item(self, item: QTreeWidgetItem):
        # Save old
        if self.current_item and self.current_editor:
            try:
                self.save_scenario_data(self.current_item, self.current_editor)
            except RuntimeError as e:
                if "has been deleted" not in str(e):
                    raise
        # Replace right panel content
        layout = self.right_panel.layout()
        for i in reversed(range(layout.count())):
            w = layout.itemAt(i).widget()
            if w:
                w.setParent(None)

        editor = ScenarioEditor()
        layout.addWidget(editor, 1)
        self.current_editor = editor
        self.current_item = item

        # Load any stored XML
        self.load_scenario_data(item, editor)

    def get_top_item(self, item: QTreeWidgetItem) -> QTreeWidgetItem:
        while item and item.parent():
            item = item.parent()
        return item

    def on_tree_click(self, item: QTreeWidgetItem):
        top = self.get_top_item(item)
        if top is None:
            return

        if top != self.current_item:
            self.build_editor_for_item(top)

        section = item.text(0) if item != top else "Base Scenario"
        if self.current_editor:
            self.current_editor.set_active_section(section)

    def open_context_menu(self, pos: QPoint):
        menu = QMenu(self)
        add_action = menu.addAction("Add Scenario")
        rename_action = menu.addAction("Rename Scenario")
        remove_action = menu.addAction("Remove Scenario")

        selected = self.tree.itemAt(pos)
        action = menu.exec(self.tree.viewport().mapToGlobal(pos))

        if action == add_action:
            name, ok = QInputDialog.getText(self, "New Scenario", "Name:")
            if ok and name.strip():
                self.add_scenario(name.strip())
        elif action == rename_action and selected:
            top = self.get_top_item(selected)
            name, ok = QInputDialog.getText(self, "Rename Scenario", "Name:", text=top.text(0))
            if ok and name.strip():
                top.setText(0, name.strip())
        elif action == remove_action and selected:
            top = self.get_top_item(selected)
            idx = self.tree.indexOfTopLevelItem(top)
            if idx >= 0:
                if self.current_item == top:
                    # clear right panel
                    layout = self.right_panel.layout()
                    for i in reversed(range(layout.count())):
                        w = layout.itemAt(i).widget()
                        if w:
                            w.setParent(None)
                    self.current_item = None
                    self.current_editor = None
                self.tree.takeTopLevelItem(idx)

    # ---- Save/Load ----
    def save_scenario_data(self, item: QTreeWidgetItem, editor: ScenarioEditor):
        scenario_xml = editor.to_xml()
        xml_str = ET.tostring(scenario_xml, encoding="unicode")
        item.setData(0, Qt.ItemDataRole.UserRole, xml_str)

    def load_scenario_data(self, item: QTreeWidgetItem, editor: ScenarioEditor):
        xml_str = item.data(0, Qt.ItemDataRole.UserRole)
        if not xml_str:
            return
        try:
            elem = ET.fromstring(xml_str)
            if elem.tag == "ScenarioEditor":
                editor.from_xml(elem)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load scenario from tree data:\n{e}")

    def save_all(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Scenarios", "", "XML Files (*.xml);;All Files (*)")
        if not path:
            return
        try:
            root = ET.Element("Scenarios")
            for i in range(self.tree.topLevelItemCount()):
                item = self.tree.topLevelItem(i)
                if item == self.current_item and self.current_editor:
                    self.save_scenario_data(item, self.current_editor)
                scen = ET.Element("Scenario", name=item.text(0))
                scen_xml = item.data(0, Qt.ItemDataRole.UserRole)
                if scen_xml:
                    scen.append(ET.fromstring(scen_xml))
                root.append(scen)
            
            # Pretty print the XML
            ET.indent(root, space="  ", level=0)
            ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
            QMessageBox.information(self, "Success", f"Scenarios saved to {path}")
            self.save_settings(path)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save scenarios:\n{e}")

    def load_from_path(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Scenarios", "", "XML Files (*.xml);;All Files (*)")
        if not path:
            return
        self.load_scenarios_from_file(path)

    def load_scenarios_from_file(self, path):
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            if root.tag != "Scenarios":
                raise ValueError("Root element must be <Scenarios>")
            # Reset current pointers to avoid using deleted items
            self.current_item = None
            self.current_editor = None
            # Clear right panel widgets
            if self.right_panel and self.right_panel.layout():
                layout = self.right_panel.layout()
                for i in reversed(range(layout.count())):
                    w = layout.itemAt(i).widget()
                    if w:
                        w.setParent(None)
            self.tree.clear()
            for scen in root.findall("Scenario"):
                name = scen.get("name", "Scenario")
                item = QTreeWidgetItem([name])
                self.tree.addTopLevelItem(item)
                for sec in SECTION_ORDER[1:]:
                    item.addChild(QTreeWidgetItem([sec]))
                item.setExpanded(True)
                scen_editor = scen.find("ScenarioEditor")
                if scen_editor is not None:
                    xml_str = ET.tostring(scen_editor, encoding="unicode")
                    item.setData(0, Qt.ItemDataRole.UserRole, xml_str)
            QMessageBox.information(self, "Success", f"Scenarios loaded from {path}")
            self.save_settings(path)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load scenarios:\n{e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MainWindow()
    w.resize(1100, 700)
    w.show()
    sys.exit(app.exec())