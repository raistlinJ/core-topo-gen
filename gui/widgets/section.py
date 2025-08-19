import xml.etree.ElementTree as ET
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QSizePolicy,
    QScrollArea, QFrame, QLayout, QComboBox, QDoubleSpinBox, QSpinBox,
    QGroupBox, QLineEdit, QFileDialog
)


class SectionWidget(QWidget):
    def __init__(self, section_name, dropdown_items=None, parent=None):
        super().__init__(parent)
        self._loading = False
        self.max_rows = 10
        self.section_name = section_name
        self.dropdown_items = dropdown_items or ["Random", "Option 1", "Option 2", "Option 3"]

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        if self.section_name == "Node Information":
            self.dropdown_items = ["Server", "Workstation", "PC", "Random"]
        elif self.section_name == "Routing":
            self.dropdown_items = ["RIP", "RIPv2", "BGP", "OSPFv2", "OSPFv3"]
        elif self.section_name == "Services":
            self.dropdown_items = ["SSH", "HTTP", "DHCPClient", "Random"]
        elif self.section_name == "Traffic":
            self.dropdown_items = ["Custom", "TCP", "UDP", "Random"]
        elif self.section_name == "Events":
            self.dropdown_items = ["Script Path"]
        elif self.section_name == "Vulnerabilities":
            self.dropdown_items = ["SSHCreds", "Bashbug", "FileArtifact", "Incompetence", "Random"]
        elif self.section_name == "Segmentation":
            self.dropdown_items = ["Firewall", "NAT", "VPN", "Random"]

        root_v = QVBoxLayout(self)
        root_v.setContentsMargins(0, 0, 0, 0)
        root_v.setSpacing(8)

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

        self.nodes_spin = None
        self.density_spin = None

        if self.section_name == "Node Information":
            nodes_row = QHBoxLayout()
            nodes_row.addWidget(QLabel("Total Nodes:"))
            self.nodes_spin = QSpinBox(); self.nodes_spin.setRange(1, 100); self.nodes_spin.setValue(1)
            nodes_row.addWidget(self.nodes_spin)
            root_v.addLayout(nodes_row)

        if self.section_name in ["Routing", "Services", "Traffic", "Events", "Vulnerabilities", "Segmentation"]:
            density_row = QHBoxLayout()
            density_row.addWidget(QLabel("Density:"))
            self.density_spin = QDoubleSpinBox(); self.density_spin.setRange(0.0, 1.0); self.density_spin.setDecimals(3); self.density_spin.setSingleStep(0.01); self.density_spin.setValue(0.5)
            density_row.addWidget(self.density_spin)
            density_row.addStretch(1)
            root_v.addLayout(density_row)

        self._dropdowns_container = QWidget(); self._dropdowns_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.dropdowns_layout = QVBoxLayout(); self.dropdowns_layout.setContentsMargins(0, 0, 0, 0); self.dropdowns_layout.setSpacing(8); self.dropdowns_layout.addStretch(1)
        self._dropdowns_container.setLayout(self.dropdowns_layout)

        self._scroll = QScrollArea(); self._scroll.setWidgetResizable(True); self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._scroll.setWidget(self._dropdowns_container)
        root_v.addWidget(self._scroll, 1)

        self.dropdown_factor_pairs = []
        self.traffic_extras = {}
        self.warning_label = QLabel(""); self.warning_label.setStyleSheet("color: red"); root_v.addWidget(self.warning_label)

        self.add_dropdown(); self.update_count_label()

    def _apply_limits(self):
        at_max = len(self.dropdown_factor_pairs) >= self.max_rows
        self.warning_label.setText("Max reached" if at_max else "")
        self.add_dropdown_btn.setEnabled(not at_max)

    def _refresh_scroll(self):
        self._dropdowns_container.adjustSize(); self._scroll.widget().adjustSize(); self._scroll.ensureVisible(0, 0, 1, 1)

    def _remove_entry(self, key):
        for entry in list(self.dropdown_factor_pairs):
            combo, spin, k, rm = entry[:4]
            if k is key:
                self.dropdown_factor_pairs.remove(entry)
                if self.section_name == "Traffic":
                    extra = self.traffic_extras.pop(k, None)
                    if extra and extra[-1] is not None:
                        box = extra[-1]; box.setParent(None); box.deleteLater()
                else:
                    layout = k
                    while layout.count():
                        item = layout.takeAt(0)
                        w = item.widget()
                        if w:
                            w.setParent(None); w.deleteLater()
                    self.dropdowns_layout.removeItem(layout); layout.setParent(None)
                break
        if not getattr(self, "_loading", False):
            self.redistribute_factors()
        self.update_count_label(); self._apply_limits(); self._refresh_scroll()

    def add_dropdown(self):
        if len(self.dropdown_factor_pairs) >= self.max_rows:
            self._apply_limits(); return

        is_traffic = (self.section_name == "Traffic")
        row = QHBoxLayout(); row.setSpacing(8)
        combo = QComboBox(); combo.addItems(self.dropdown_items)
        idx = combo.findText("Random")
        if idx >= 0:
            combo.setCurrentIndex(idx)
        row.addWidget(combo)

        script_path_edit = None; script_browse_btn = None
        if self.section_name == "Events":
            script_path_edit = QLineEdit(); script_path_edit.setPlaceholderText("Enter script path...")
            script_browse_btn = QPushButton("Browse"); script_browse_btn.setFixedWidth(70)

            def browse_script():
                file_path, _ = QFileDialog.getOpenFileName(self, "Select Script File", "", "All Files (*)")
                if file_path:
                    script_path_edit.setText(file_path)
            script_browse_btn.clicked.connect(browse_script)
            row.addWidget(script_path_edit, 1); row.addWidget(script_browse_btn)

        row.addWidget(QLabel("Weight:"))
        factor_spin = QDoubleSpinBox(); factor_spin.setRange(0.0, 1.0); factor_spin.setDecimals(3); factor_spin.setSingleStep(0.05); factor_spin.valueChanged.connect(self.validate_factors)
        row.addWidget(factor_spin)

        remove_btn = QPushButton("Remove"); remove_btn.setFixedWidth(70); row.addWidget(remove_btn); row.addStretch(1)

        if is_traffic:
            group_box = QGroupBox(f"Profile {len(self.traffic_extras) + 1}"); group_box.setFlat(True)
            group_box.setStyleSheet("QGroupBox { background: transparent; border: 1px solid rgba(0,0,0,40); margin-top: 12px; } QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }")
            group_box.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            group_v = QVBoxLayout(group_box); group_v.setContentsMargins(8, 8, 8, 8); group_v.setSpacing(6); group_v.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)

            pattern_row = QHBoxLayout(); pattern_row.setSpacing(8); pattern_row.addWidget(QLabel("Pattern:"))
            pattern_combo = QComboBox(); pattern_combo.addItems(["1kbps", "5kbps", "Jitter", "Periodic (repeat every x seconds)", "Random", "Custom"]); pattern_row.addWidget(pattern_combo)

            extra_row = QHBoxLayout(); extra_row.setSpacing(8)
            rate_label = QLabel("Rate (kbps):"); rate_spin = QDoubleSpinBox(); rate_spin.setRange(0.1, 100000.0); rate_spin.setDecimals(1); rate_spin.setValue(64.0)
            period_label = QLabel("Period (s):"); period_spin = QDoubleSpinBox(); period_spin.setRange(0.1, 3600.0); period_spin.setDecimals(1); period_spin.setValue(1.0)
            jitter_label = QLabel("Jitter (%):"); jitter_spin = QDoubleSpinBox(); jitter_spin.setRange(0.0, 100.0); jitter_spin.setDecimals(1); jitter_spin.setValue(10.0)
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
                group_box.adjustSize(); group_box.updateGeometry()

            pattern_combo.currentTextChanged.connect(_apply_vis); _apply_vis()

            group_v.addLayout(row); group_v.addLayout(pattern_row); group_v.addLayout(extra_row)
            self.dropdowns_layout.insertWidget(self.dropdowns_layout.count() - 1, group_box)
            key = group_box
            self.traffic_extras[key] = (pattern_combo, rate_spin, period_spin, jitter_spin, group_box)
            remove_btn.clicked.connect(lambda: self._remove_entry(key))
            self.dropdown_factor_pairs.append((combo, factor_spin, key, remove_btn))
        else:
            self.dropdowns_layout.insertLayout(self.dropdowns_layout.count() - 1, row)
            key = row
            remove_btn.clicked.connect(lambda: self._remove_entry(key))
            if self.section_name == "Events":
                self.dropdown_factor_pairs.append((combo, factor_spin, key, remove_btn, script_path_edit, script_browse_btn))
            else:
                self.dropdown_factor_pairs.append((combo, factor_spin, key, remove_btn))

        if not getattr(self, "_loading", False):
            self.redistribute_factors()
        self.update_count_label(); self._apply_limits(); self._refresh_scroll()

    def clear_all_rows(self):
        for entry in list(self.dropdown_factor_pairs):
            combo, spin, key = entry[:3]
            if self.section_name == "Traffic":
                extra = self.traffic_extras.pop(key, None)
                if extra and extra[-1] is not None:
                    box = extra[-1]; box.setParent(None); box.deleteLater()
            else:
                layout = key
                while layout.count():
                    item = layout.takeAt(0)
                    w = item.widget()
                    if w:
                        w.setParent(None); w.deleteLater()
                self.dropdowns_layout.removeItem(layout); layout.setParent(None)
        self.dropdown_factor_pairs.clear(); self._refresh_scroll()

    def redistribute_factors(self):
        if getattr(self, "_loading", False):
            return
        n = len(self.dropdown_factor_pairs)
        if n == 0:
            return
        even = round(1.0 / n, 3)
        for i, entry in enumerate(self.dropdown_factor_pairs):
            _, spin = entry[:2]
            if i < n - 1:
                spin.blockSignals(True); spin.setValue(even); spin.blockSignals(False)
            else:
                resid = max(0.0, 1.0 - sum(e[1].value() for e in self.dropdown_factor_pairs[:-1]))
                spin.blockSignals(True); spin.setValue(round(resid, 3)); spin.blockSignals(False)

    def validate_factors(self):
        if getattr(self, "_loading", False):
            return
        s = round(sum(entry[1].value() for entry in self.dropdown_factor_pairs), 3)
        self.warning_label.setText(f"Warning: weights sum to {s:.3f} (should be 1.000)" if abs(s - 1.0) > 0.005 else "")

    def update_count_label(self):
        try:
            current = len(self.dropdown_factor_pairs)
            max_rows = getattr(self, 'max_rows', 10)
            if hasattr(self, 'count_label') and self.count_label is not None:
                self.count_label.setText(f"({current}/{max_rows})")
        except Exception:
            pass

    def to_xml(self):
        section_elem = ET.Element("section", name=self.section_name)
        if self.nodes_spin is not None and self.section_name == "Node Information":
            section_elem.set("total_nodes", str(self.nodes_spin.value()))
        if self.density_spin is not None:
            section_elem.set("density", f"{self.density_spin.value():.3f}")
        for entry in self.dropdown_factor_pairs:
            combo, factor, key = entry[:3]
            item_elem = ET.SubElement(section_elem, "item")
            item_elem.set("selected", combo.currentText())
            item_elem.set("factor", f"{factor.value():.3f}")
            if self.section_name == "Events" and len(entry) >= 6:
                script_path_edit = entry[4]
                if script_path_edit and script_path_edit.text().strip():
                    item_elem.set("script_path", script_path_edit.text().strip())
            if self.section_name == "Traffic" and key in self.traffic_extras:
                pattern_combo, rate_spin, period_spin, jitter_spin, _box = self.traffic_extras[key]
                sel = pattern_combo.currentText()
                item_elem.set("pattern", sel)
                item_elem.set("rate_kbps", f"{rate_spin.value():.1f}")
                item_elem.set("period_s", f"{period_spin.value():.1f}")
                item_elem.set("jitter_pct", f"{jitter_spin.value():.1f}")
        return section_elem

    def from_xml(self, section_elem):
        self._loading = True
        if self.nodes_spin is not None and self.section_name == "Node Information":
            v = section_elem.get("total_nodes")
            if v:
                self.nodes_spin.setValue(int(v))
        if self.density_spin is not None:
            density_val = section_elem.get("density")
            if density_val:
                try:
                    self.density_spin.setValue(float(density_val))
                except Exception:
                    pass
        self.clear_all_rows()
        items = section_elem.findall("item")
        if not items:
            self.add_dropdown(); self._loading = False; return
        for item_elem in items:
            self.add_dropdown()
            entry = self.dropdown_factor_pairs[-1]
            combo, factor, key = entry[:3]
            sel = item_elem.get("selected", "Random")
            idx = combo.findText(sel)
            if idx >= 0:
                combo.setCurrentIndex(idx)
            try:
                factor.setValue(float(item_elem.get("factor", "1.0")))
            except Exception:
                pass
            if self.section_name == "Events" and len(entry) >= 6:
                script_path_edit = entry[4]
                script_path = item_elem.get("script_path", "")
                if script_path_edit and script_path:
                    script_path_edit.setText(script_path)
            if self.section_name == "Traffic" and key in self.traffic_extras:
                pattern_combo, rate_spin, period_spin, jitter_spin, box = self.traffic_extras[key]
                psel = item_elem.get("pattern", "Random")
                idxp = pattern_combo.findText(psel)
                if idxp >= 0:
                    pattern_combo.setCurrentIndex(idxp)
                try:
                    if item_elem.get("rate_kbps") is not None:
                        rate_spin.setValue(float(item_elem.get("rate_kbps")))
                    if item_elem.get("period_s") is not None:
                        period_spin.setValue(float(item_elem.get("period_s")))
                    if item_elem.get("jitter_pct") is not None:
                        jitter_spin.setValue(float(item_elem.get("jitter_pct")))
                except Exception:
                    pass
        self._loading = False
        self.validate_factors(); self._refresh_scroll()
