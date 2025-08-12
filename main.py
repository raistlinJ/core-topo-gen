import sys
import os
import xml.etree.ElementTree as ET
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QComboBox, QDoubleSpinBox,
    QPushButton, QVBoxLayout, QHBoxLayout, QGroupBox,
    QFileDialog, QScrollArea, QTreeWidget, QTreeWidgetItem, QMenu, QSplitter,
    QInputDialog, QLineEdit, QMessageBox, QMainWindow
)
from PyQt6.QtCore import Qt, QPoint


class SectionWidget(QWidget):
    def __init__(self, section_name, dropdown_items=None, parent=None):
        super().__init__(parent)

        if dropdown_items is None:
            dropdown_items = ["Random", "Option 1", "Option 2", "Option 3"]

        self.dropdown_items = dropdown_items

        self.setLayout(QVBoxLayout())
        self.section_name = section_name

        top_row = QHBoxLayout()
        label = QLabel(section_name)
        top_row.addWidget(label)

        self.add_dropdown_btn = QPushButton("Add Dropdown")
        self.add_dropdown_btn.clicked.connect(self.add_dropdown)
        top_row.addWidget(self.add_dropdown_btn)
        top_row.addStretch()
        self.layout().addLayout(top_row)

        self.dropdowns_layout = QVBoxLayout()
        self.layout().addLayout(self.dropdowns_layout)

        self.warning_label = QLabel("")
        self.warning_label.setStyleSheet("color: red")
        self.layout().addWidget(self.warning_label)

        # Store tuples: (combo, spinbox, row_layout, remove_button)
        self.dropdown_factor_pairs = []

        self.add_dropdown()

    def add_dropdown(self):
        row = QHBoxLayout()

        combo = QComboBox()
        combo.addItems(self.dropdown_items)
        index = combo.findText("Random")
        if index >= 0:
            combo.setCurrentIndex(index)
        row.addWidget(combo)

        factor_label = QLabel("Factor:")
        row.addWidget(factor_label)

        factor_spin = QDoubleSpinBox()
        factor_spin.setRange(0.0, 1.0)
        factor_spin.setSingleStep(0.05)
        factor_spin.setDecimals(3)
        factor_spin.setFixedWidth(80)
        factor_spin.valueChanged.connect(self.validate_factors)
        row.addWidget(factor_spin)

        remove_btn = QPushButton("Remove")
        remove_btn.setFixedWidth(70)
        row.addWidget(remove_btn)

        self.dropdowns_layout.addLayout(row)
        self.dropdown_factor_pairs.append((combo, factor_spin, row, remove_btn))

        remove_btn.clicked.connect(lambda _, r=row: self.remove_dropdown(r))

        self.redistribute_factors()
        self.update_remove_buttons()
        self.validate_factors()

    def remove_dropdown(self, row):
        # Find index of the row to remove
        index_to_remove = -1
        for i, (_, _, layout, _) in enumerate(self.dropdown_factor_pairs):
            if layout == row:
                index_to_remove = i
                break
        if index_to_remove == -1:
            return

        # Remove all widgets in the layout
        layout = self.dropdown_factor_pairs[index_to_remove][2]
        for i in reversed(range(layout.count())):
            widget = layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()

        self.dropdowns_layout.removeItem(layout)
        self.dropdown_factor_pairs.pop(index_to_remove)

        self.redistribute_factors()
        self.update_remove_buttons()
        self.validate_factors()

    def update_remove_buttons(self):
        # Disable remove button if only one dropdown left
        count = len(self.dropdown_factor_pairs)
        for _, _, _, remove_btn in self.dropdown_factor_pairs:
            remove_btn.setEnabled(count > 1)

    def redistribute_factors(self):
        count = len(self.dropdown_factor_pairs)
        if count == 0:
            return
        even_value = 1.0 / count
        for _, factor, _, _ in self.dropdown_factor_pairs:
            factor.blockSignals(True)
            factor.setValue(even_value)
            factor.blockSignals(False)

    def validate_factors(self):
        total = sum(factor.value() for _, factor, _, _ in self.dropdown_factor_pairs)
        if abs(total - 1.0) > 0.01:
            self.warning_label.setText(f"Factors must sum to 1. Current sum: {total:.3f}")
            self.add_dropdown_btn.setEnabled(False)
        else:
            self.warning_label.setText("")
            self.add_dropdown_btn.setEnabled(True)

    def to_xml(self):
        section_elem = ET.Element("section", name=self.section_name)
        for combo, factor, _, _ in self.dropdown_factor_pairs:
            item_elem = ET.SubElement(section_elem, "item")
            selected_text = combo.currentText()
            item_elem.set("selected", selected_text)
            item_elem.set("factor", f"{factor.value():.3f}")
        return section_elem

    def from_xml(self, section_elem):
        # Clear existing dropdowns
        for i in reversed(range(self.dropdowns_layout.count())):
            layout_item = self.dropdowns_layout.itemAt(i)
            if layout_item:
                for j in reversed(range(layout_item.count())):
                    widget = layout_item.itemAt(j).widget()
                    if widget:
                        widget.deleteLater()
                self.dropdowns_layout.removeItem(layout_item)
        self.dropdown_factor_pairs.clear()

        # Add dropdowns from XML without redistributing
        for item_elem in section_elem.findall("item"):
            row = QHBoxLayout()

            combo = QComboBox()
            combo.addItems(self.dropdown_items)
            selected = item_elem.get("selected", "Random")
            idx = combo.findText(selected)
            if idx >= 0:
                combo.setCurrentIndex(idx)
            row.addWidget(combo)

            factor_label = QLabel("Factor:")
            row.addWidget(factor_label)

            factor_spin = QDoubleSpinBox()
            factor_spin.setRange(0.0, 1.0)
            factor_spin.setSingleStep(0.05)
            factor_spin.setDecimals(3)
            factor_spin.setFixedWidth(80)
            factor_spin.blockSignals(True)
            try:
                factor_val = float(item_elem.get("factor", "0.0"))
            except ValueError:
                factor_val = 0.0
            factor_spin.setValue(factor_val)
            factor_spin.blockSignals(False)
            factor_spin.valueChanged.connect(self.validate_factors)
            row.addWidget(factor_spin)

            remove_btn = QPushButton("Remove")
            remove_btn.setFixedWidth(70)
            row.addWidget(remove_btn)

            self.dropdowns_layout.addLayout(row)
            self.dropdown_factor_pairs.append((combo, factor_spin, row, remove_btn))

            remove_btn.clicked.connect(lambda _, r=row: self.remove_dropdown(r))

        self.update_remove_buttons()
        self.validate_factors()


class BaseScenarioWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout()
        label = QLabel("Base Scenario File:")
        self.file_input = QLineEdit()
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_file)
        layout.addWidget(label)
        layout.addWidget(self.file_input)
        layout.addWidget(browse_button)
        self.setLayout(layout)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_input.setText(file_path)

    def to_xml(self):
        elem = ET.Element("BaseScenario")
        elem.set("filepath", self.file_input.text())
        return elem

    def from_xml(self, elem):
        filepath = elem.get("filepath", "")
        self.file_input.setText(filepath)


class ScenarioEditor(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        content_widget = QWidget()
        content_layout = QVBoxLayout()

        self.base_scenario_group = QGroupBox("Base Scenario")
        base_layout = QVBoxLayout()
        self.base_scenario_widget = BaseScenarioWidget()
        base_layout.addWidget(self.base_scenario_widget)
        self.base_scenario_group.setLayout(base_layout)
        content_layout.addWidget(self.base_scenario_group)

        self.sections = {}
        section_names = [
            "Node Information",
            "Routing",
            "Services",
            "Traffic",
            "Events",
            "Vulnerabilities",  # Moved above "Other"
            "Other"
        ]
        for name in section_names:
            section = SectionWidget(name)
            self.sections[name] = section
            group_box = QGroupBox(name)
            group_layout = QVBoxLayout()
            group_layout.addWidget(section)
            group_box.setLayout(group_layout)
            content_layout.addWidget(group_box)

        content_layout.addStretch()
        content_widget.setLayout(content_layout)
        scroll_area.setWidget(content_widget)

        layout.addWidget(scroll_area)
        self.setLayout(layout)

    def to_xml(self):
        scenario_elem = ET.Element("ScenarioEditor")
        scenario_elem.append(self.base_scenario_widget.to_xml())
        for name, section in self.sections.items():
            scenario_elem.append(section.to_xml())
        return scenario_elem

    def from_xml(self, scenario_elem):
        base_elem = scenario_elem.find("BaseScenario")
        if base_elem is not None:
            self.base_scenario_widget.from_xml(base_elem)

        for section_elem in scenario_elem.findall("section"):
            name = section_elem.get("name", "")
            if name in self.sections:
                self.sections[name].from_xml(section_elem)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Scenario Editor")

        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")

        save_action = file_menu.addAction("Save")
        save_action.triggered.connect(self.save_to_file)

        load_action = file_menu.addAction("Load")
        load_action.triggered.connect(self.load_from_file)

        splitter = QSplitter()
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.open_context_menu)
        self.tree.itemClicked.connect(self.load_scenario)

        self.right_panel = QWidget()
        splitter.addWidget(self.tree)
        splitter.addWidget(self.right_panel)
        splitter.setSizes([200, 600])

        central_widget = QWidget()
        layout = QHBoxLayout()
        layout.addWidget(splitter)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        self.current_editor = None
        self.current_item = None

        self.default_save_path = "scenarios.xml"
        if os.path.exists(self.default_save_path):
            self.load_from_path(self.default_save_path)

    def closeEvent(self, event):
        if self.current_editor and self.current_item:
            self.save_scenario_data(self.current_item, self.current_editor)
        try:
            self.save_all(self.default_save_path)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to autosave scenarios:\n{str(e)}")
        event.accept()

    def open_context_menu(self, position: QPoint):
        menu = QMenu()
        add_action = menu.addAction("Add New Scenario")

        selected = self.tree.currentItem()
        if selected:
            remove_action = menu.addAction("Remove Selected Scenario")

        action = menu.exec(self.tree.viewport().mapToGlobal(position))
        if action == add_action:
            name, ok = QInputDialog.getText(self, "New Scenario", "Enter scenario name:")
            if ok and name.strip():
                new_item = QTreeWidgetItem([name.strip()])
                self.tree.addTopLevelItem(new_item)
        elif selected and action == remove_action:
            index = self.tree.indexOfTopLevelItem(selected)
            if index >= 0:
                self.tree.takeTopLevelItem(index)
                if selected == self.current_item:
                    self.clear_right_panel()

    def load_scenario(self, item):
        if self.current_editor and self.current_item:
            self.save_scenario_data(self.current_item, self.current_editor)

        editor = ScenarioEditor()
        self.load_scenario_data(item, editor)

        self.clear_right_panel()

        if not self.right_panel.layout():
            self.right_panel.setLayout(QVBoxLayout())
        self.right_panel.layout().addWidget(editor)

        self.current_editor = editor
        self.current_item = item

    def clear_right_panel(self):
        if self.right_panel.layout() and self.right_panel.layout().count() > 0:
            old_widget = self.right_panel.layout().itemAt(0).widget()
            if old_widget:
                old_widget.deleteLater()
                self.right_panel.layout().removeWidget(old_widget)
        self.current_editor = None
        self.current_item = None

    def save_scenario_data(self, item, editor):
        scenario_xml = editor.to_xml()
        xml_str = ET.tostring(scenario_xml, encoding="unicode")
        item.setData(0, Qt.ItemDataRole.UserRole, xml_str)

    def load_scenario_data(self, item, editor):
        xml_str = item.data(0, Qt.ItemDataRole.UserRole)
        if xml_str:
            try:
                root = ET.fromstring(xml_str)
                editor.from_xml(root)
            except ET.ParseError:
                QMessageBox.warning(self, "Error", "Failed to parse scenario data.")

    def save_to_file(self):
        if self.current_editor and self.current_item:
            self.save_scenario_data(self.current_item, self.current_editor)

        path, _ = QFileDialog.getSaveFileName(self, "Save Scenarios", "", "XML Files (*.xml)")
        if path:
            self.save_all(path)

    def load_from_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Scenarios", "", "XML Files (*.xml)")
        if path:
            self.load_from_path(path)

    def save_all(self, path):
        if self.current_editor and self.current_item:
            self.save_scenario_data(self.current_item, self.current_editor)

        root = ET.Element("Scenarios")
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            item_elem = ET.SubElement(root, "Scenario")
            item_elem.set("name", item.text(0))
            data_xml_str = item.data(0, Qt.ItemDataRole.UserRole)
            if data_xml_str:
                try:
                    data_elem = ET.fromstring(data_xml_str)
                    item_elem.append(data_elem)
                except ET.ParseError:
                    pass
        tree = ET.ElementTree(root)
        try:
            tree.write(path, encoding="utf-8", xml_declaration=True)
            QMessageBox.information(self, "Success", f"Scenarios saved to {path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save file:\n{str(e)}")

    def load_from_path(self, path):
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            self.tree.clear()
            self.clear_right_panel()
            for scenario_elem in root.findall("Scenario"):
                name = scenario_elem.get("name", "Unnamed")
                item = QTreeWidgetItem([name])
                scenario_xml_str = ""
                scenario_editor_elem = scenario_elem.find("ScenarioEditor")
                if scenario_editor_elem is not None:
                    scenario_xml_str = ET.tostring(scenario_editor_elem, encoding="unicode")
                elif len(scenario_elem):
                    scenario_xml_str = ET.tostring(scenario_elem[0], encoding="unicode")
                if scenario_xml_str:
                    item.setData(0, Qt.ItemDataRole.UserRole, scenario_xml_str)
                self.tree.addTopLevelItem(item)
            QMessageBox.information(self, "Success", f"Scenarios loaded from {path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load scenarios:\n{str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.resize(900, 600)
    window.show()
    sys.exit(app.exec())
