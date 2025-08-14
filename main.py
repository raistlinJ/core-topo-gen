import sys
import os
import subprocess
import xml.etree.ElementTree as ET
import json

from PyQt6.QtCore import Qt, QPoint, QStandardPaths
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QComboBox, QDoubleSpinBox, QSpinBox, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, QGroupBox, QFileDialog, QScrollArea, QTreeWidget, QTreeWidgetItem, QMenu, QSplitter, QInputDialog, QLineEdit, QMessageBox, QMainWindow, QStackedWidget, QSizePolicy)


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

        # Collect nodes
        def tagname(el):
            return el.tag.split('}')[-1].lower()

        nodes = {}
        for el in root.iter():
            if tagname(el) == "node":
                nid = el.get("id") or el.get("name") or el.findtext("id") or el.findtext("name")
                if nid:
                    nodes[nid] = el
        if not nodes:
            for el in root.iter():
                if tagname(el) in {"host","router","switch","pc","server","workstation"}:
                    nid = el.get("id") or el.get("name") or el.findtext("id") or el.findtext("name")
                    if nid:
                        nodes[nid] = el

        # Connections
        connections = []
        for el in root.iter():
            t = tagname(el)
            if t in {"link","connection","edge","net","interfacepair","wire"}:
                a = el.get("node1") or el.get("src") or el.get("source") or el.get("from")
                b = el.get("node2") or el.get("dst") or el.get("target") or el.get("to")
                if not a or not b:
                    refs = []
                    for ch in el.iter():
                        for key in ("node","node_id","src","dst","source","target","from","to","end1","end2"):
                            v = ch.get(key) or ch.findtext(key)
                            if v:
                                refs.append(v)
                                break
                        if len(refs) >= 2:
                            break
                    if len(refs) >= 2:
                        a, b = refs[0], refs[1]
                if a and b:
                    connections.append((a, b))

        # Services
        services = []
        for el in root.iter():
            if "service" in tagname(el):
                name = el.get("name") or (el.text.strip() if el.text else None)
                if name:
                    services.append(name)

        # Traffic flows
        flows = []
        for el in root.iter():
            t = tagname(el)
            if "flow" in t or "traffic" in t:
                src = el.get("src") or el.get("source") or el.get("from") or el.findtext("src") or el.findtext("from")
                dst = el.get("dst") or el.get("target") or el.get("to") or el.findtext("dst") or el.findtext("to")
                desc = el.get("type") or el.get("protocol") or el.findtext("type") or el.findtext("protocol") or ""
                if src or dst or desc:
                    flows.append({"src": src, "dst": dst, "desc": desc})

        # Non-connected nodes
        degrees = {nid: 0 for nid in nodes}
        for a, b in connections:
            if a in degrees: degrees[a] += 1
            if b in degrees: degrees[b] += 1
        non_connected = [nid for nid, d in degrees.items() if d == 0]

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
            label = f"{(f['src'] or '?')} → {(f['dst'] or '?')}"
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
    def __init__(self, section_name, dropdown_items=None, parent=None):
        super().__init__(parent)
        self.max_rows = 10

        if dropdown_items is None:
            dropdown_items = ["Random", "Option 1", "Option 2", "Option 3"]

        self.section_name = section_name
        self.dropdown_items = dropdown_items

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
            # Changed to segmentation-specific items
            self.dropdown_items = ["Firewall", "NAT", "VPN", "Random"]

        # UI skeleton
        self.setLayout(QVBoxLayout())
        self.traffic_extras = {}  # map main row layout -> (pattern_combo, pattern_row, extra_row, rate_spin, period_spin, jitter_spin, group_box)

        top_row = QHBoxLayout()
        top_row.addWidget(QLabel(section_name))

        # Update button text for different sections
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
        elif self.section_name == "Vulnerabilities":
            self.add_dropdown_btn.setText("Add vulnerability")
        self.add_dropdown_btn.clicked.connect(self.add_dropdown)
        top_row.addWidget(self.add_dropdown_btn)
        
        self.normalize_btn = QPushButton("Normalize")
        self.normalize_btn.setToolTip("Evenly redistribute weights so the total is 1.000")
        self.normalize_btn.clicked.connect(self.normalize_factors)
        top_row.addWidget(self.normalize_btn)
        self.count_label = QLabel("")
        self.count_label.setStyleSheet("color:#666; margin-left:6px;")
        top_row.addWidget(self.count_label)
        top_row.addStretch()
        self.layout().addLayout(top_row)

        # Node Information and Segmentation: total nodes/segments (between top row and dropdowns)
        self.nodes_spin = None
        if self.section_name == "Node Information":
            nodes_row = QHBoxLayout()
            nodes_row.addWidget(QLabel("Total Nodes:"))
            self.nodes_spin = QSpinBox()
            self.nodes_spin.setRange(1, 100)
            self.nodes_spin.setValue(1)
            nodes_row.addWidget(self.nodes_spin)
            self.layout().addLayout(nodes_row)
        elif self.section_name == "Segmentation":
            # Add total segments spinner for segmentation section
            segments_row = QHBoxLayout()
            segments_row.addWidget(QLabel("Total Segments:"))
            self.nodes_spin = QSpinBox()
            self.nodes_spin.setRange(1, 100)
            self.nodes_spin.setValue(1)
            segments_row.addWidget(self.nodes_spin)
            self.layout().addLayout(segments_row)

        # Where the rows live (in a scroll area to avoid overlap)

        self.dropdowns_layout = QVBoxLayout()

        self.dropdowns_layout.setSpacing(6)

        self.dropdowns_layout.setContentsMargins(0, 0, 0, 0)

        self._dropdowns_container = QWidget()

        self._dropdowns_container.setLayout(self.dropdowns_layout)

        self._scroll = QScrollArea()

        self._scroll.setWidgetResizable(True)

        self._scroll.setWidget(self._dropdowns_container)

        self.layout().addWidget(self._scroll)

        # Store tuples: (combo, spinbox, row_layout, remove_button)
        self.dropdown_factor_pairs = []

        self.warning_label = QLabel("")
        self.warning_label.setStyleSheet("color: red")
        self.layout().addWidget(self.warning_label)

        # Start with one row
        self.add_dropdown()
        self.update_count_label()

    # --- Row management ---
    def add_dropdown(self):
        # Enforce max rows per section
        if len(self.dropdown_factor_pairs) >= getattr(self, 'max_rows', 10):
            try:
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.information(self, "Limit reached", f"You can add at most {self.max_rows} entries in {self.section_name}.")
            except Exception:
                pass
            return
        is_traffic = (self.section_name == "Traffic")
        profile_index = len(self.traffic_extras) + 1 if is_traffic else None

        # Main row
        row = QHBoxLayout()

        row.setSpacing(8)
        combo = QComboBox()
        combo.addItems(self.dropdown_items)
        if self.section_name == "Segmentation":
            try:
                combo.setCurrentText("Random")
            except Exception:
                pass
        idx = combo.findText("Random")
        if idx >= 0:
            combo.setCurrentIndex(idx)
        row.addWidget(combo)

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
# Defaults
        pattern_combo = pattern_row = extra_row = None
        rate_spin = period_spin = jitter_spin = None

        if is_traffic:
            group_box = QGroupBox(f"Profile {profile_index}")
            group_box.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
            group_v = QVBoxLayout(group_box)

            group_v.setContentsMargins(8, 8, 8, 8)
            group_v.setSpacing(6)
            # Pattern row
            pattern_row = QHBoxLayout()
            pattern_row.setSpacing(8)
            pattern_label = QLabel("Pattern:")
            pattern_combo = QComboBox()
            pattern_combo.addItems(["1kbps", "5kbps", "Jitter", "Periodic (1s)", "Periodic (5s)", "Random", "Custom"])
            pattern_row.addWidget(pattern_label)
            pattern_row.addWidget(pattern_combo)

            # Extra inputs row
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

            # Visibility logic
            def _apply_vis():
                sel = pattern_combo.currentText()
                show_rate = (sel == "Custom")
                show_period = sel.startswith("Periodic")
                show_jitter = (sel == "Jitter")
                rate_label.setVisible(show_rate); rate_spin.setVisible(show_rate)
                period_label.setVisible(show_period); period_spin.setVisible(show_period)
                jitter_label.setVisible(show_jitter); jitter_spin.setVisible(show_jitter)
                if sel == "Periodic (1s)":
                    period_spin.setValue(1.0)
                elif sel == "Periodic (5s)":
                    period_spin.setValue(5.0)
            pattern_combo.currentTextChanged.connect(lambda _: _apply_vis())
            _apply_vis()

            # Assemble group
            group_v.addLayout(row)
            group_v.addLayout(pattern_row)
            group_v.addLayout(extra_row)
            self.dropdowns_layout.addWidget(group_box)
        else:
            # Non-traffic rows go directly in the container
            self.dropdowns_layout.addLayout(row)

        # Bookkeeping
        self.dropdown_factor_pairs.append((combo, factor_spin, row, remove_btn))
        if is_traffic:
            self.traffic_extras[row] = (pattern_combo, pattern_row, extra_row, rate_spin, period_spin, jitter_spin, group_box)

        remove_btn.clicked.connect(lambda _, r=row: self.remove_dropdown(r))

        self.redistribute_factors()
        self.update_remove_buttons()
        self.validate_factors()
        self.update_count_label()

    def remove_dropdown(self, row):
        # Locate record
        index_to_remove = -1
        for i, (_, _, layout, _) in enumerate(self.dropdown_factor_pairs):
            if layout == row:
                index_to_remove = i
                break
        if index_to_remove == -1:
            return

        layout = self.dropdown_factor_pairs[index_to_remove][2]

        # Traffic entries are wrapped in a group box
        if layout in self.traffic_extras:
            vals = self.traffic_extras.pop(layout)
            if len(vals) == 7:
                pattern_combo, pattern_row, extra_row, rate_spin, period_spin, jitter_spin, group_box = vals
            else:
                pattern_combo, pattern_row, extra_row, rate_spin, period_spin, jitter_spin = vals
                group_box = None

            if group_box is not None:
                group_box.deleteLater()
                try:
                    self.dropdowns_layout.removeWidget(group_box)
                except Exception:
                    pass
        else:
            # Non-traffic: remove widgets from the row
            for i in reversed(range(layout.count())):
                w = layout.itemAt(i).widget()
                if w:
                    w.deleteLater()
            self.dropdowns_layout.removeItem(layout)

        self.dropdown_factor_pairs.pop(index_to_remove)

        self.redistribute_factors()
        self.update_remove_buttons()
        self.validate_factors()
        self.update_count_label()

    def update_remove_buttons(self):
        count = len(self.dropdown_factor_pairs)
        for _, _, _, btn in self.dropdown_factor_pairs:
            btn.setEnabled(count > 1)

    
    def redistribute_factors(self):
        count = len(self.dropdown_factor_pairs)
        if count == 0:
            return
        # Use the same precision as spinboxes to avoid rounding drift
        decimals = 3
        even = round(1.0 / count, decimals)
        running = 0.0
        for i, (_, spin, _, _) in enumerate(self.dropdown_factor_pairs):
            spin.blockSignals(True)
            if i < count - 1:
                spin.setValue(even)
                running += even
            else:
                # Last one gets the remainder to force exact sum = 1.0 (to displayed precision)
                remainder = round(1.0 - running, decimals)
                # Clamp just in case
                remainder = max(0.0, min(1.0, remainder))
                spin.setValue(remainder)
            spin.blockSignals(False)
    
    def validate_factors(self):
        total = sum(spin.value() for _, spin, _, _ in self.dropdown_factor_pairs)
        at_max = len(self.dropdown_factor_pairs) >= getattr(self, 'max_rows', 10)
        # Compare using the same precision as the spinboxes to avoid float drift
        if round(total, 3) != 1.000:
            self.warning_label.setText(f"Weights must sum to 1. Current sum: {total:.3f}")
            self.add_dropdown_btn.setEnabled(False)
        else:
            self.warning_label.setText("Max reached" if at_max else "")
            self.add_dropdown_btn.setEnabled(not at_max)
    
    def normalize_factors(self):
        """Evenly redistribute weights so they sum to 1.000 at the current precision."""
        self.redistribute_factors()
        self.validate_factors()

    def update_count_label(self):
        try:
            current = len(self.dropdown_factor_pairs)
            max_rows = getattr(self, 'max_rows', 10)
            if hasattr(self, 'count_label') and self.count_label is not None:
                self.count_label.setText(f"({current}/{max_rows})")
        except Exception:
            pass


    # --- XML ---
    def to_xml(self):
        section_elem = ET.Element("section", name=self.section_name)
        # Node Information and Segmentation
        if self.nodes_spin is not None:
            if self.section_name == "Node Information":
                section_elem.set("total_nodes", str(self.nodes_spin.value()))
            elif self.section_name == "Segmentation":
                section_elem.set("total_segments", str(self.nodes_spin.value()))
        for combo, factor, layout, _ in self.dropdown_factor_pairs:
            item_elem = ET.SubElement(section_elem, "item")
            item_elem.set("selected", combo.currentText())
            item_elem.set("factor", f"{factor.value():.3f}")
            if self.section_name == "Traffic" and layout in self.traffic_extras:
                pattern_combo, pattern_row, extra_row, rate_spin, period_spin, jitter_spin, group_box = self.traffic_extras[layout]
                sel = pattern_combo.currentText()
                item_elem.set("pattern", sel)
                if sel == "Custom":
                    item_elem.set("pattern_rate_kbps", f"{rate_spin.value():.1f}")
                elif sel.startswith("Periodic"):
                    item_elem.set("pattern_period_s", f"{period_spin.value():.1f}")
                elif sel == "Jitter":
                    item_elem.set("pattern_jitter_pct", f"{jitter_spin.value():.1f}")
        return section_elem

    def from_xml(self, section_elem):
        # Clear container
        while self.dropdowns_layout.count():
            item = self.dropdowns_layout.takeAt(0)
            if item is None:
                break
            lay = item.layout()
            if lay:
                while lay.count():
                    w = lay.takeAt(0).widget()
                    if w:
                        w.deleteLater()

        self.dropdown_factor_pairs.clear()
        self.traffic_extras.clear()

        # Node Information and Segmentation
        if self.nodes_spin is not None:
            try:
                if self.section_name == "Node Information":
                    self.nodes_spin.setValue(int(section_elem.get("total_nodes", "1")))
                elif self.section_name == "Segmentation":
                    self.nodes_spin.setValue(int(section_elem.get("total_segments", "1")))
            except Exception:
                self.nodes_spin.setValue(1)

        items = list(section_elem.findall("item"))
        # Cap to max_rows if file has more
        items = items[:getattr(self, 'max_rows', 10)]
        if not items:
            self.add_dropdown()
            return

        for item_elem in items:
            row = QHBoxLayout()

            combo = QComboBox()
            combo.addItems(self.dropdown_items)
            if self.section_name == "Segmentation":
                try:
                    combo.setCurrentText("Random")
                except Exception:
                    pass
            sel = item_elem.get("selected", "Random")
            idx = combo.findText(sel)
            if idx >= 0:
                combo.setCurrentIndex(idx)
            row.addWidget(combo)

            row.addWidget(QLabel("Weight:"))
            factor_spin = QDoubleSpinBox()
            factor_spin.setRange(0.0, 1.0)
            factor_spin.setDecimals(3)
            factor_spin.setSingleStep(0.05)
            try:
                factor_spin.setValue(float(item_elem.get("factor", "1.0")))
            except Exception:
                pass
            factor_spin.valueChanged.connect(self.validate_factors)
            row.addWidget(factor_spin)

            remove_btn = QPushButton("Remove")
            remove_btn.setFixedWidth(70)
            row.addWidget(remove_btn)

            # Add to container (grouped for Traffic)
            if self.section_name == "Traffic":
                profile_index = len(self.traffic_extras) + 1
                group_box = QGroupBox(f"Profile {profile_index}")
                group_v = QVBoxLayout(group_box)

                group_v.addLayout(row)

                pattern_row = QHBoxLayout()
                pattern_label = QLabel("Pattern:")
                pattern_combo = QComboBox()
                pattern_combo.addItems(["1kbps", "5kbps", "Jitter", "Periodic (1s)", "Periodic (5s)", "Random", "Custom"])
                pv = item_elem.get("pattern", "Random")
                ii = pattern_combo.findText(pv)
                if ii >= 0:
                    pattern_combo.setCurrentIndex(ii)
                pattern_row.addWidget(pattern_label)
                pattern_row.addWidget(pattern_combo)
                group_v.addLayout(pattern_row)

                extra_row = QHBoxLayout()
                rate_label = QLabel("Rate (kbps):"); rate_spin = QDoubleSpinBox(); rate_spin.setRange(0.1, 100000.0); rate_spin.setDecimals(1); rate_spin.setValue(64.0)
                period_label = QLabel("Period (s):"); period_spin = QDoubleSpinBox(); period_spin.setRange(0.1, 3600.0); period_spin.setDecimals(1); period_spin.setValue(1.0)
                jitter_label = QLabel("Jitter (%):"); jitter_spin = QDoubleSpinBox(); jitter_spin.setRange(0.0, 100.0); jitter_spin.setDecimals(1); jitter_spin.setValue(10.0)
                for w in (rate_label, rate_spin, period_label, period_spin, jitter_label, jitter_spin):
                    extra_row.addWidget(w)
                group_v.addLayout(extra_row)

                # Visibility and saved values
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
                pattern_combo.currentTextChanged.connect(lambda _: _apply_vis())
                try: rate_spin.setValue(float(item_elem.get("pattern_rate_kbps", rate_spin.value())))
                except Exception: pass
                try: period_spin.setValue(float(item_elem.get("pattern_period_s", period_spin.value())))
                except Exception: pass
                try: jitter_spin.setValue(float(item_elem.get("pattern_jitter_pct", jitter_spin.value())))
                except Exception: pass
                _apply_vis()

                self.dropdowns_layout.addWidget(group_box)
                # Bookkeeping
                self.dropdown_factor_pairs.append((combo, factor_spin, row, remove_btn))
                self.traffic_extras[row] = (pattern_combo, pattern_row, extra_row, rate_spin, period_spin, jitter_spin, group_box)
            else:
                self.dropdowns_layout.addLayout(row)
                self.dropdown_factor_pairs.append((combo, factor_spin, row, remove_btn))

            remove_btn.clicked.connect(lambda _, r=row: self.remove_dropdown(r))

        self.update_remove_buttons()
        self.validate_factors()
        self.update_count_label()


# ---------------------------
# Scenario Editor (stacked view)
# ---------------------------
class ScenarioEditor(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        self.stacked = QStackedWidget()
        self.pages = {}
        self.sections = {}

        # Base Scenario page
        base_page = QWidget()
        base_v = QVBoxLayout()
        self.base_scenario_group = QGroupBox("Base Scenario")
        base_layout = QVBoxLayout()
        self.base_scenario_widget = BaseScenarioWidget()
        base_layout.addWidget(self.base_scenario_widget)
        self.base_scenario_group.setLayout(base_layout)
        base_v.addWidget(self.base_scenario_group)
        base_v.addStretch()
        base_page.setLayout(base_v)
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
            pv = QVBoxLayout()
            group_box = QGroupBox(name)
            group_layout = QVBoxLayout()
            group_layout.addWidget(section)
            group_box.setLayout(group_layout)
            pv.addWidget(group_box)
            pv.addStretch()
            page.setLayout(pv)

            self.stacked.addWidget(page)
            self.pages[name] = page

        # Notes page
        notes_page = QWidget()
        notes_v = QVBoxLayout()
        self.notes_widget = NotesWidget()
        notes_group = QGroupBox("Notes")
        notes_layout = QVBoxLayout()
        notes_layout.addWidget(self.notes_widget)
        notes_group.setLayout(notes_layout)
        notes_v.addWidget(notes_group)
        notes_v.addStretch()
        notes_page.setLayout(notes_v)
        self.stacked.addWidget(notes_page)
        self.pages["Notes"] = notes_page

        layout.addWidget(self.stacked)
        self.setLayout(layout)

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
        self.right_panel.setLayout(QVBoxLayout())

        splitter.addWidget(self.tree)
        splitter.addWidget(self.right_panel)
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
        for i in reversed(range(self.right_panel.layout().count())):
            w = self.right_panel.layout().itemAt(i).widget()
            if w:
                w.setParent(None)

        editor = ScenarioEditor()
        self.right_panel.layout().addWidget(editor)
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
                    for i in reversed(range(self.right_panel.layout().count())):
                        w = self.right_panel.layout().itemAt(i).widget()
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
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save scenarios:\n{e}")

    def load_from_path(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Scenarios", "", "XML Files (*.xml);;All Files (*)")
        if not path:
            return
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
                for i in reversed(range(self.right_panel.layout().count())):
                    w = self.right_panel.layout().itemAt(i).widget()
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
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load scenarios:\n{e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MainWindow()
    w.resize(1100, 700)
    w.show()
    sys.exit(app.exec())