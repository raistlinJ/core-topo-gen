import sys
import os
import json
sys.path.append(os.getcwd())
from webapp import app_backend

app = app_backend.app

def test():
    scenario = "Scenario 1"
    # Reuse valid XML path from previous reproduction
    xml_path = "/Users/jcacosta/Documents/core-topo-gen/outputs/scenarios-20260209-112030/Scenario_1.xml"
    
    with app.test_request_context(
        '/api/flag-sequencing/sequence_preview_plan',
        method='POST',
        json={
            'scenario': scenario,
            'preset': '',
            'length': 3,
            'details': True,
            'preview_plan': xml_path,
            'allow_node_duplicates': True,
            'goal_facts': {
                'artifacts': ['Flag(flag_id)', 'File(path)'],
                'fields': []
            }
        }
    ):
        print(f"Calling sequence_preview_plan for {scenario}...")
        try:
            resp = app_backend.api_flow_sequence_preview_plan()
            if isinstance(resp, tuple):
                resp = resp[0]
            data = resp.get_json()
            
            # Check goal facts in response
            # Note: API might not return 'goal_facts' directly, but rather as part of the plan or metadata.
            # Let's dump relevant fields.
            print("Response Keys:", data.keys())
            
            # In the frontend, goal_facts often come from initial/goal override inputs or the scenario definition.
            # But the 'sequence' logic uses them to pick generators.
            # Let's see if we can infer what goal facts were used.
            
            # The API doesn't seem to echo goal_facts unless they were passed in?
            # Or maybe they are in the validation output?
            
            if 'validation' in data:
                print("Validation:", json.dumps(data['validation'], indent=2))
                
        except Exception as e:
            print(f"Exception: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    test()
