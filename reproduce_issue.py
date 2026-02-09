import sys
import os
import json
from flask import Flask, request

# Add current directory to path
sys.path.append(os.getcwd())

from webapp import app_backend

app = app_backend.app

def test():
    scenario = "Scenario 1"
    # Find the XML file
    xml_path = "/Users/jcacosta/Documents/core-topo-gen/outputs/scenarios-20260209-112030/Scenario_1.xml"
    if not os.path.exists(xml_path):
        print(f"Error: XML file {xml_path} not found")
        # Try to find any XML
        import glob
        xmls = glob.glob("outputs/scenarios-*/Scenario_1.xml")
        if xmls:
            xml_path = os.path.abspath(xmls[-1])
            print(f"Using found XML: {xml_path}")
        else:
            print("No XML found")
            return

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
        print(f"Calling sequence_preview_plan for {scenario}...")
        try:
            resp = app_backend.api_flow_sequence_preview_plan()
            if isinstance(resp, tuple):
                resp = resp[0]
            data = resp.get_json()
            # print(json.dumps(data, indent=2))
            
            assignments = data.get('flag_assignments', [])
            print(f"Generated {len(assignments)} assignments")
            
            for i, a in enumerate(assignments):
                print(f"Assignment {i}: {a.get('id')} -> Node {a.get('node_id')}")
                print(f"  Injects: {a.get('inject_files')}")
                if data.get('ok') is False:
                   print(f"  Error: {data.get('error')}")

            # Now try resolve
            if data.get('ok') is not False:
                chain_ids = [n['id'] for n in data.get('chain', [])]
                print("\nCalling prepare_preview_for_execute...")
                
                with app.test_request_context(
                    '/api/flag-sequencing/prepare_preview_for_execute',
                    method='POST',
                    json={
                        'scenario': scenario,
                        'length': len(chain_ids),
                        'chain_ids': chain_ids,
                        'preview_plan': xml_path,
                        'mode': 'resolve',
                        'best_effort': True
                    }
                ):
                    resp2 = app_backend.api_flow_prepare_preview_for_execute()
                    if isinstance(resp2, tuple):
                        resp2 = resp2[0]
                    data2 = resp2.get_json()
                    
                    assignments2 = data2.get('flag_assignments', [])
                    print(f"Resolved {len(assignments2)} assignments")
                    for i, a in enumerate(assignments2):
                        print(f"Assignment {i}:")
                        print(f"  Injects: {a.get('inject_files')}")
                        print(f"  Resolved Outputs: {a.get('resolved_outputs')}")
                        print(f"  Outputs: {a.get('outputs')}")
        
        except Exception as e:
            print(f"Exception: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test()
