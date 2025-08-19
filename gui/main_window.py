import os
import sys
import json
import xml.etree.ElementTree as ET
from typing import Optional
from PyQt6.QtCore import Qt, QPoint, QStandardPaths, QProcess
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QSplitter, QTreeWidget, QTreeWidgetItem,
    QMenu, QInputDialog, QMessageBox, QFileDialog, QApplication, QHeaderView, QSizePolicy
)
from .editor import ScenarioEditor

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

        self.current_item: Optional[QTreeWidgetItem] = None
        self.current_editor: Optional[ScenarioEditor] = None
        self.settings_file = self.get_settings_file_path()
        self.current_file: Optional[str] = None

        splitter = QSplitter(self)
        self.tree = QTreeWidget(); self.tree.setHeaderLabels(["Scenarios"])
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.open_context_menu)
        self.tree.itemClicked.connect(self.on_tree_click)

        self.right_panel = QWidget(); self.right_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        right_layout = QVBoxLayout(self.right_panel); right_layout.setContentsMargins(0, 0, 0, 0); right_layout.setSpacing(0)

        splitter.addWidget(self.tree); splitter.addWidget(self.right_panel)
        self.tree.setMinimumWidth(220)
        splitter.setStretchFactor(0, 0); splitter.setStretchFactor(1, 1)
        self.setCentralWidget(splitter)

        menubar = self.menuBar(); file_menu = menubar.addMenu("File")
        save_action = file_menu.addAction("Save"); save_action.setShortcut("Ctrl+S"); save_action.triggered.connect(self.save_to_current)
        save_as_action = file_menu.addAction("Save As…"); save_as_action.setShortcut("Ctrl+Shift+S"); save_as_action.triggered.connect(self.save_all)
        load_action = file_menu.addAction("Load…"); load_action.setShortcut("Ctrl+O"); load_action.triggered.connect(self.load_from_path)

        self.load_last_file_or_defaults()

    def get_settings_file_path(self):
        app_data_dir = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation)
        if not os.path.exists(app_data_dir):
            os.makedirs(app_data_dir)
        return os.path.join(app_data_dir, "scenario_editor_settings.json")

    def save_settings(self, last_file_path=None):
        settings = {"last_file": last_file_path}
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save settings: {e}")

    def load_settings(self):
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load settings: {e}")
        return {}

    def load_last_file_or_defaults(self):
        settings = self.load_settings()
        last_file = settings.get("last_file")
        if last_file and os.path.exists(last_file):
            try:
                self.load_scenarios_from_file(last_file)
                return
            except Exception as e:
                print(f"Warning: Could not load last file {last_file}: {e}")
        self.add_scenario("Scenario 1")

    def add_scenario(self, name: str):
        item = QTreeWidgetItem([name]); self.tree.addTopLevelItem(item)
        for sec in SECTION_ORDER[1:]:
            item.addChild(QTreeWidgetItem([sec]))
        item.setExpanded(True)
        self.build_editor_for_item(item)

    def build_editor_for_item(self, item: QTreeWidgetItem):
        if self.current_item and self.current_editor:
            try:
                self.save_scenario_data(self.current_item, self.current_editor)
            except RuntimeError as e:
                if "has been deleted" not in str(e):
                    raise
        layout = self.right_panel.layout()
        for i in reversed(range(layout.count())):
            w = layout.itemAt(i).widget()
            if w:
                w.setParent(None)
        editor = ScenarioEditor(); layout.addWidget(editor, 1)
        self.current_editor = editor; self.current_item = item
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
        generate_action = menu.addAction("Generate in CORE…")

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
                    layout = self.right_panel.layout()
                    for i in reversed(range(layout.count())):
                        w = layout.itemAt(i).widget()
                        if w:
                            w.setParent(None)
                    self.current_item = None; self.current_editor = None
                self.tree.takeTopLevelItem(idx)
        elif action == generate_action and selected:
            top = self.get_top_item(selected)
            scenario_name = top.text(0)
            if self.current_item and self.current_editor:
                try:
                    self.save_scenario_data(self.current_item, self.current_editor)
                except RuntimeError:
                    pass
            if self.current_file:
                self._write_to_path(self.current_file); xml_path = self.current_file
            else:
                self.save_all()
                if not self.current_file:
                    QMessageBox.information(self, "Cancelled", "Generation cancelled: no file selected.")
                    return
                xml_path = self.current_file

            # QProcess + progress
            if hasattr(self, "_gen_process") and isinstance(getattr(self, "_gen_process"), QProcess):
                try:
                    if self._gen_process.state() != QProcess.ProcessState.NotRunning:  # type: ignore[attr-defined]
                        QMessageBox.information(self, "Busy", "A generation is already in progress.")
                        return
                except Exception:
                    pass

            self._gen_stdout = ""; self._gen_stderr = ""
            self._gen_process = QProcess(self)

            def _read_out():
                try:
                    data = bytes(self._gen_process.readAllStandardOutput()); self._gen_stdout += data.decode("utf-8", errors="ignore")
                except Exception:
                    pass
            def _read_err():
                try:
                    data = bytes(self._gen_process.readAllStandardError()); self._gen_stderr += data.decode("utf-8", errors="ignore")
                except Exception:
                    pass
            self._gen_process.readyReadStandardOutput.connect(_read_out)
            self._gen_process.readyReadStandardError.connect(_read_err)

            from PyQt6.QtWidgets import QProgressDialog
            self._gen_progress = QProgressDialog("Generating scenario in CORE…", "Cancel", 0, 0, self)
            self._gen_progress.setWindowModality(Qt.WindowModality.ApplicationModal)
            self._gen_progress.setAutoClose(True); self._gen_progress.setAutoReset(True); self._gen_progress.setMinimumDuration(0)

            def _on_cancel():
                try:
                    self._gen_process.kill()
                except Exception:
                    pass
            self._gen_progress.canceled.connect(_on_cancel)

            def _on_finished(code: int, status: QProcess.ExitStatus):
                try:
                    self._gen_progress.close()
                except Exception:
                    pass
                err = (self._gen_stderr or "").strip(); out = (self._gen_stdout or "").strip()
                if code != 0:
                    if "No module named 'core'" in err or "No module named core" in err:
                        QMessageBox.critical(self, "Missing CORE Python Package", "The current Python environment cannot import the CORE library (module 'core').\n\nRun this from an environment where CORE is installed and available to Python, or start this app from the same environment used by core-daemon.")
                    elif status == QProcess.ExitStatus.CrashExit:
                        QMessageBox.warning(self, "Generator Crashed", err or out or f"Exit code: {code}")
                    else:
                        QMessageBox.warning(self, "Generator Error", err or out or f"Exit code: {code}")
                else:
                    QMessageBox.information(self, "Completed", "CORE scenario generation completed.")
                self._gen_stdout = ""; self._gen_stderr = ""

            def _on_error(_err: QProcess.ProcessError):
                try:
                    self._gen_progress.close()
                except Exception:
                    pass
                err = (self._gen_stderr or "").strip(); out = (self._gen_stdout or "").strip()
                QMessageBox.warning(self, "Generator Error", err or out or "Failed to start generator.")
                self._gen_stdout = ""; self._gen_stderr = ""

            self._gen_process.finished.connect(_on_finished)
            self._gen_process.errorOccurred.connect(_on_error)
            self._gen_process.setProgram(sys.executable)
            self._gen_process.setArguments(["-m", "core_topo_gen.cli", "--xml", xml_path, "--scenario", scenario_name])
            try:
                self._gen_process.start(); self._gen_progress.show()
            except Exception as e:
                try:
                    self._gen_progress.close()
                except Exception:
                    pass
                QMessageBox.warning(self, "Error", f"Failed to launch generator:\n{e}")

    def save_scenario_data(self, item: QTreeWidgetItem, editor: ScenarioEditor):
        scenario_xml = editor.to_xml(); xml_str = ET.tostring(scenario_xml, encoding="unicode")
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

    def _write_to_path(self, path: str):
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
            wrote_pretty = False
            try:
                from lxml import etree as LET  # type: ignore
                raw = ET.tostring(root, encoding="utf-8"); lroot = LET.fromstring(raw)
                pretty = LET.tostring(lroot, pretty_print=True, xml_declaration=True, encoding="utf-8")
                with open(path, "wb") as f: f.write(pretty)
                wrote_pretty = True
            except Exception:
                import xml.etree.ElementTree as _ET
                tree = _ET.ElementTree(root)
                try:
                    _ET.indent(tree, space="  ", level=0)  # type: ignore[attr-defined]
                except Exception:
                    pass
                tree.write(path, encoding="utf-8", xml_declaration=True)
            self.current_file = path; self.save_settings(path)
            QMessageBox.information(self, "Saved", f"Scenarios saved to {path}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save scenarios:\n{e}")

    def save_to_current(self):
        target = self.current_file
        if not target:
            settings = self.load_settings(); target = settings.get("last_file")
        if target:
            self._write_to_path(target)
        else:
            self.save_all()

    def save_all(self):
        default_dir = ""
        if self.current_file:
            default_dir = self.current_file
        else:
            settings = self.load_settings(); last_file = settings.get("last_file")
            if last_file:
                default_dir = last_file
        path, _ = QFileDialog.getSaveFileName(self, "Save Scenarios", default_dir, "XML Files (*.xml);;All Files (*)")
        if not path:
            return
        self._write_to_path(path)

    def load_from_path(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Scenarios", "", "XML Files (*.xml);;All Files (*)")
        if not path:
            return
        self.load_scenarios_from_file(path)

    def load_scenarios_from_file(self, path):
        try:
            tree = ET.parse(path); root = tree.getroot()
            if root.tag != "Scenarios":
                raise ValueError("Root element must be <Scenarios>")
            self.current_item = None; self.current_editor = None
            if self.right_panel and self.right_panel.layout():
                layout = self.right_panel.layout()
                for i in reversed(range(layout.count())):
                    w = layout.itemAt(i).widget()
                    if w:
                        w.setParent(None)
            self.tree.clear()
            for scen in root.findall("Scenario"):
                name = scen.get("name", "Scenario")
                item = QTreeWidgetItem([name]); self.tree.addTopLevelItem(item)
                for sec in SECTION_ORDER[1:]:
                    item.addChild(QTreeWidgetItem([sec]))
                item.setExpanded(True)
                scen_editor = scen.find("ScenarioEditor")
                if scen_editor is not None:
                    xml_str = ET.tostring(scen_editor, encoding="unicode")
                    item.setData(0, Qt.ItemDataRole.UserRole, xml_str)
            QMessageBox.information(self, "Success", f"Scenarios loaded from {path}")
            self.save_settings(path); self.current_file = path
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load scenarios:\n{e}")
