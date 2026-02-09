import sys
import os
import json
import xml.etree.ElementTree as ET
sys.path.append(os.getcwd())
from webapp import app_backend

app = app_backend.app

def test():
    scenario = "Scenario 1"
    # Use the path we saw in the debug log
    xml_path = "/Users/jcacosta/Documents/core-topo-gen/outputs/scenarios-20260208-225951/Scenario_1.xml"
    
    if not os.path.exists(xml_path):
        print(f"FAILURE: XML path {xml_path} does not exist.")
        return
        
    print(f"Using XML for test: {xml_path}")
    
    # We need to simulate a valid request to save_flow_substitutions
    # First, let's get the current state to have valid chain_ids and flag_assignments
    with app.test_request_context(
        '/api/flag-sequencing/sequence_preview_plan',
        method='POST',
        json={
            'scenario': scenario,
            'preset': '',
            'length': 3,
            'details': True,
            'preview_plan': xml_path,
            'allow_node_duplicates': True
        }
    ):
        resp = app_backend.api_flow_sequence_preview_plan()
        if isinstance(resp, tuple): resp = resp[0]
        data = resp.get_json()
        chain_ids = [n['id'] for n in data.get('chain', [])]
        assignments = data.get('flag_assignments', [])

    print(f"Initial sequence generated with {len(chain_ids)} nodes.")

    # Now call save_flow_substitutions with goal_facts override containing Flag(flag_id)
    goal_facts = {
        'artifacts': ['Flag(flag_id)', 'File(path)', 'NewArtifact'],
        'fields': ['test_field']
    }
    
    with app.test_request_context(
        '/api/flag-sequencing/save_flow_substitutions',
        method='POST',
        json={
            'scenario': scenario,
            'chain_ids': chain_ids,
            'preview_plan': xml_path,
            'flag_assignments': assignments,
            'goal_facts': goal_facts
        }
    ):
        print("Calling save_flow_substitutions with goal_facts override...")
        resp_save = app_backend.api_flow_save_flow_substitutions()
        if isinstance(resp_save, tuple): resp_save = resp_save[0]
        data_save = resp_save.get_json()
        print("Save OK:", data_save.get('ok'))
        if not data_save.get('ok'):
            print("Error:", data_save.get('error'))
            return

    # Now read the XML and check FlowState
    print(f"Checking XML: {xml_path}")
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    # The XML might have multiple Scenarios, find the right one
    scen_norm = app_backend._normalize_scenario_label(scenario)
    found_scen = None
    if root.tag == 'Scenario' and app_backend._normalize_scenario_label(root.get('name')) == scen_norm:
        found_scen = root
    else:
        for s in root.findall('.//Scenario'):
            if app_backend._normalize_scenario_label(s.get('name')) == scen_norm:
                found_scen = s
                break
    
    if found_scen is None:
        print(f"FAILURE: Scenario '{scenario}' not found in XML.")
        return

    flow_state_el = found_scen.find(".//FlowState")
    if flow_state_el is not None:
        flow_state = json.loads(flow_state_el.text)
        saved_goal_facts = flow_state.get('goal_facts')
        print("Saved Goal Facts:", json.dumps(saved_goal_facts, indent=2))
        
        if saved_goal_facts is None:
            print("FAILURE: goal_facts is None in FlowState.")
            return

        artifacts = saved_goal_facts.get('artifacts', [])
        if 'Flag(flag_id)' in artifacts:
            print("SUCCESS: Flag(flag_id) found in saved goal facts!")
        else:
            print("FAILURE: Flag(flag_id) NOT found in saved goal facts.")
    else:
        print("FAILURE: FlowState element not found in scenario in XML.")

if __name__ == "__main__":
    test()
