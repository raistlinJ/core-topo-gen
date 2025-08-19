import xml.etree.ElementTree as ET
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit


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
        self._loading = True
        note_elem = section_elem.find("notes")
        self.text.setPlainText(note_elem.text if note_elem is not None and note_elem.text else "")
