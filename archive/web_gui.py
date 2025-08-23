from flask import Flask, render_template_string, request, redirect, url_for, flash, send_file
from io import BytesIO
import xml.etree.ElementTree as ET

app = Flask(__name__)
app.secret_key = "secret"

# In-memory storage of scenarios, keyed by name
# Each scenario is a dict with keys: 'base_file', 'sections'
# 'sections' is a dict of section_name -> list of dicts with keys: selected, factor, radio_choice
scenarios = {}

# Default section names
SECTION_NAMES = [
  "Node Information",
  "Routing",
  "Services",
  "Traffic",
  "Segmentation",
  "Events",
  "Other"
]

# Default fallback options shown when a section has no specific list
DROPDOWN_OPTIONS = ["Random"]

# Per-section dropdown options; ensure selectable types like CUSTOM appear where applicable
DROPDOWN_OPTIONS_BY_SECTION = {
  # Keep Traffic kinds aligned with generator expectations
  "Traffic": ["Random", "TCP", "UDP"],
  # Segmentation supports Firewall, NAT, and CUSTOM (plugin-backed)
  "Segmentation": ["Random", "Firewall", "NAT", "CUSTOM"],
}

# Traffic pattern options supported by auto-generator
TRAFFIC_PATTERN_OPTIONS = [
  "continuous", "periodic", "burst", "poisson", "ramp"
]

# HTML template using Jinja2 syntax
HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <title>Scenario Editor</title>
  <style>
    body { font-family: Arial, sans-serif; margin:0; }
    #container { display: flex; height: 100vh; }
    #sidebar { width: 250px; border-right: 1px solid #ccc; padding: 10px; overflow-y: auto; }
    #main { flex: 1; padding: 10px; overflow-y: auto; }
    ul { list-style: none; padding-left: 0; }
    li { margin-bottom: 8px; }
    .section { border: 1px solid #ddd; padding: 10px; margin-bottom: 15px; }
    .dropdown-row { display: flex; gap: 10px; align-items: center; margin-bottom: 5px; }
    label { font-weight: bold; }
    input[type=number] { width: 80px; }
    .error { color: red; }
    button { margin-top: 5px; }
  </style>
</head>
<body>
  <div id="container">
    <div id="sidebar">
      <h3>Scenarios</h3>
      <form method="post" action="{{ url_for('add_scenario') }}">
        <input type="text" name="scenario_name" placeholder="New scenario name" required>
        <button type="submit">Add</button>
      </form>
      <ul>
      {% for name in scenarios %}
        <li>
          <a href="{{ url_for('edit_scenario', scenario_name=name) }}">{{ name }}</a>
          <form method="post" action="{{ url_for('delete_scenario', scenario_name=name) }}" style="display:inline;">
            <button type="submit" onclick="return confirm('Remove scenario {{ name }}?')">Remove</button>
          </form>
        </li>
      {% else %}
        <li>No scenarios yet</li>
      {% endfor %}
      </ul>
      <hr>
      <form method="post" action="{{ url_for('upload_xml') }}" enctype="multipart/form-data">
        <label><b>Load XML file:</b></label><br>
        <input type="file" name="xml_file" required>
        <button type="submit">Load</button>
      </form>
      <form method="get" action="{{ url_for('download_xml') }}">
        <button type="submit">Download XML</button>
      </form>
    </div>
    <div id="main">
      {% if scenario %}
      <h2>Editing scenario: {{ scenario_name }}</h2>
      <form method="post" action="{{ url_for('save_scenario', scenario_name=scenario_name) }}">
        <div class="section">
          <label>Base Scenario File:</label><br>
          <input type="text" name="base_file" value="{{ scenario['base_file'] }}" style="width: 80%;" placeholder="File path or URL">
        </div>
        {% for section in section_names %}
        <div class="section">
          <label>{{ section }}</label>
          <div id="{{ section }}-items">
            {% for idx, item in enumerate(scenario['sections'][section]) %}
            <div class="dropdown-row">
              <select name="{{ section }}_selected_{{ idx }}">
                {% set options_for_section = dropdown_by_section.get(section, dropdown_options) %}
                {% for option in options_for_section %}
                  <option value="{{ option }}" {% if option == item.selected %}selected{% endif %}>{{ option }}</option>
                {% endfor %}
              </select>
              {% if section == 'Traffic' %}
              <label>Pattern:</label>
              <select name="{{ section }}_pattern_{{ idx }}">
                {% for p in traffic_pattern_options %}
                  <option value="{{ p }}" {% if p == (item.get('pattern') or '') %}selected{% endif %}>{{ p if p else 'default' }}</option>
                {% endfor %}
              </select>
              {% endif %}
              <label>Factor:</label>
              <input type="number" step="0.01" min="0" max="1" name="{{ section }}_factor_{{ idx }}" value="{{ item.factor }}" required>
              <label>Type:</label>
              <label><input type="radio" name="{{ section }}_radio_{{ idx }}" value="factor" {% if item.radio_choice == 'factor' %}checked{% endif %}> Factor</label>
              <label><input type="radio" name="{{ section }}_radio_{{ idx }}" value="random" {% if item.radio_choice == 'random' %}checked{% endif %}> Random</label>
              <button name="remove_{{ section }}_{{ idx }}" value="remove" type="submit">Remove</button>
            </div>
            {% endfor %}
          </div>
          <button name="add_{{ section }}" value="add" type="submit">Add Dropdown</button>
        </div>
        {% endfor %}
        <div style="color: red;">
          {% if error %}{{ error }}{% endif %}
        </div>
        <button type="submit">Save Scenario</button>
      </form>
      {% else %}
        <p>Select or create a scenario from the left.</p>
      {% endif %}
    </div>
  </div>
</body>
</html>
"""

def default_scenario():
    # Create default data structure for a new scenario
    sections = {}
    for sec in SECTION_NAMES:
        # Start with one dropdown with 'Random' selected, factor = 1, radio_choice 'random'
        sections[sec] = [{
            'selected': 'Random',
            'factor': 1.0,
            'radio_choice': 'random'
        }]
    return {
        'base_file': '',
        'sections': sections
    }


@app.route("/", methods=["GET"])
def index():
    scenario_name = request.args.get("scenario")
    scenario = scenarios.get(scenario_name)
    return render_template_string(
        HTML_TEMPLATE,
        scenarios=sorted(scenarios.keys()),
  scenario=scenario,
  scenario_name=scenario_name,
  section_names=SECTION_NAMES,
  dropdown_options=DROPDOWN_OPTIONS,
  dropdown_by_section=DROPDOWN_OPTIONS_BY_SECTION,
  traffic_pattern_options=TRAFFIC_PATTERN_OPTIONS,
        error=None
    )


@app.route("/add", methods=["POST"])
def add_scenario():
    name = request.form.get("scenario_name", "").strip()
    if not name:
        flash("Scenario name cannot be empty.")
    elif name in scenarios:
        flash("Scenario name already exists.")
    else:
        scenarios[name] = default_scenario()
    return redirect(url_for("index", scenario=name))


@app.route("/delete/<scenario_name>", methods=["POST"])
def delete_scenario(scenario_name):
    if scenario_name in scenarios:
        del scenarios[scenario_name]
    return redirect(url_for("index"))


@app.route("/edit/<scenario_name>", methods=["GET", "POST"])
def edit_scenario(scenario_name):
  if scenario_name not in scenarios:
    flash("Scenario not found.")
    return redirect(url_for("index"))

  scenario = scenarios[scenario_name]
  error = None

  if request.method == "POST":
    # Handle add/remove dropdowns, parse form inputs, validate factors
    new_sections = {}

    # Update base_file
    base_file = request.form.get("base_file", "")
    scenario['base_file'] = base_file

    for section in SECTION_NAMES:
      items = []
      idx = 0
      while True:
        sel_key = f"{section}_selected_{idx}"
        factor_key = f"{section}_factor_{idx}"
        radio_key = f"{section}_radio_{idx}"
        pattern_key = f"{section}_pattern_{idx}"
        remove_key = f"remove_{section}_{idx}"

        if sel_key not in request.form:
          break

        if remove_key in request.form:
          # This item is removed, skip
          idx += 1
          continue

        selected = request.form.get(sel_key)
        try:
          factor = float(request.form.get(factor_key))
        except (ValueError, TypeError):
          factor = 0.0
        radio_choice = request.form.get(radio_key, "random")
        item_rec = {
          'selected': selected,
          'factor': factor,
          'radio_choice': radio_choice
        }
        if section == "Traffic":
          item_rec['pattern'] = request.form.get(pattern_key, "")
        items.append(item_rec)
        idx += 1

      # Add a blank entry when requested
      add_btn = f"add_{section}"
      if add_btn in request.form:
        rec = {
          'selected': 'Random',
          'factor': 0.0,
          'radio_choice': 'random'
        }
        if section == "Traffic":
          rec['pattern'] = ""
        items.append(rec)

      # Normalize factors to sum to 1 if >0
      total_factor = sum(item['factor'] for item in items)
      if total_factor == 0 and len(items) > 0:
        equal_factor = 1.0 / len(items)
        for item in items:
          item['factor'] = equal_factor
      elif total_factor > 0:
        for item in items:
          item['factor'] = item['factor'] / total_factor

      # Check factor sum to ~1
      if abs(sum(item['factor'] for item in items) - 1.0) > 0.01:
        error = f"Factors in section '{section}' must sum to 1."

      new_sections[section] = items

    if not error:
      scenario['sections'] = new_sections
      flash("Scenario saved.")
      return redirect(url_for("edit_scenario", scenario_name=scenario_name))

  return render_template_string(
    HTML_TEMPLATE,
    scenarios=sorted(scenarios.keys()),
    scenario=scenario,
    scenario_name=scenario_name,
    section_names=SECTION_NAMES,
    dropdown_options=DROPDOWN_OPTIONS,
    dropdown_by_section=DROPDOWN_OPTIONS_BY_SECTION,
    traffic_pattern_options=TRAFFIC_PATTERN_OPTIONS,
    error=error
  )


@app.route("/save_xml")
def download_xml():
  root = ET.Element("Scenarios")
  for name, scenario in scenarios.items():
    scenario_elem = ET.SubElement(root, "Scenario", name=name)
    base_elem = ET.SubElement(scenario_elem, "BaseScenario")
    base_elem.set("filepath", scenario['base_file'])
    for section_name, items in scenario['sections'].items():
      section_elem = ET.SubElement(scenario_elem, "section", name=section_name)
      for item in items:
        item_elem = ET.SubElement(section_elem, "item")
        item_elem.set("selected", item['selected'])
        item_elem.set("factor", f"{item['factor']:.3f}")
        item_elem.set("radio_choice", item['radio_choice'])
        if section_name == "Traffic":
          item_elem.set("pattern", (item.get('pattern') or ""))
  tree = ET.ElementTree(root)
  bio = BytesIO()
  tree.write(bio, encoding='utf-8', xml_declaration=True)
  bio.seek(0)
  return send_file(
    bio,
    mimetype='application/xml',
    as_attachment=True,
    download_name='scenarios.xml'
  )


@app.route("/upload_xml", methods=["POST"])
def upload_xml():
  xml_file = request.files.get("xml_file")
  if not xml_file:
    flash("No file uploaded.")
    return redirect(url_for("index"))

  try:
    tree = ET.parse(xml_file)
    root = tree.getroot()
    scenarios.clear()
    for scenario_elem in root.findall("Scenario"):
      name = scenario_elem.get("name", "Unnamed")
      base_file = ""
      sections = {sec: [] for sec in SECTION_NAMES}

      base_elem = scenario_elem.find("BaseScenario")
      if base_elem is not None:
        base_file = base_elem.get("filepath", "")

      for section_elem in scenario_elem.findall("section"):
        sec_name = section_elem.get("name", "")
        if sec_name in sections:
          items = []
          for item_elem in section_elem.findall("item"):
            selected = item_elem.get("selected", "Random")
            factor = float(item_elem.get("factor", "0"))
            radio_choice = item_elem.get("radio_choice", "random")
            rec = {
              "selected": selected,
              "factor": factor,
              "radio_choice": radio_choice
            }
            if sec_name == "Traffic":
              rec["pattern"] = item_elem.get("pattern", "")
            items.append(rec)
          if items:
            sections[sec_name] = items

      scenarios[name] = {
        "base_file": base_file,
        "sections": sections
      }
    flash("Scenarios loaded from XML.")
  except Exception as e:
    flash(f"Failed to load XML: {e}")

  return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
