import xml.etree.ElementTree as ET
from typing import Optional
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QStackedWidget, QGroupBox
from .widgets.base_scenario import BaseScenarioWidget
from .widgets.section import SectionWidget
from .widgets.notes import NotesWidget


class ScenarioEditor(QWidget):
    def __init__(self):
        super().__init__()
        self.setObjectName("ScenarioEditorRoot")
        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        self.stacked = QStackedWidget(); root.addWidget(self.stacked, 1)
        self.pages = {}
        self.sections = {}

        # Base Scenario
        base_page = QWidget(); base_v = QVBoxLayout(base_page); base_v.setContentsMargins(8, 8, 8, 8)
        self.base_scenario_group = QGroupBox("Base Scenario")
        base_layout = QVBoxLayout(); self.base_scenario_widget = BaseScenarioWidget(); base_layout.addWidget(self.base_scenario_widget)
        self.base_scenario_group.setLayout(base_layout); base_v.addWidget(self.base_scenario_group, 1)
        self.stacked.addWidget(base_page); self.pages["Base Scenario"] = base_page

        # Sections
        for name in [
            "Node Information",
            "Routing",
            "Services",
            "Traffic",
            "Events",
            "Vulnerabilities",
            "Segmentation",
        ]:
            section = SectionWidget(name); self.sections[name] = section
            page = QWidget(); pv = QVBoxLayout(page); pv.setContentsMargins(8, 8, 8, 8)
            group_box = QGroupBox(name); gl = QVBoxLayout(); gl.addWidget(section, 1); group_box.setLayout(gl); pv.addWidget(group_box, 1)
            self.stacked.addWidget(page); self.pages[name] = page

        # Notes
        notes_page = QWidget(); notes_v = QVBoxLayout(notes_page); notes_v.setContentsMargins(8, 8, 8, 8)
        self.notes_widget = NotesWidget(); notes_group = QGroupBox("Notes"); nl = QVBoxLayout(); nl.addWidget(self.notes_widget, 1); notes_group.setLayout(nl)
        notes_v.addWidget(notes_group, 1); self.stacked.addWidget(notes_page); self.pages["Notes"] = notes_page

    def set_active_section(self, section_name: Optional[str]):
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
