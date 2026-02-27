import re
import shlex

def _normalize_scenario_label(value):
    if value is None:
        return ''
    text = value if isinstance(value, str) else str(value)
    text = text.strip().lower()
    return re.sub(r'\s+', ' ', text)

def test_replacement():
    scenario_label = "scenario 1"
    scenario_norm = _normalize_scenario_label(scenario_label)
    # This is what app_backend.py does currently (implicit assumption of replacement) however
    # re.sub('\s+', ' ', text) keeps spaces as single spaces.
    # But usually directory naming replaces spaces with underscores?
    # Let's check if there is another normalization function.
    
    # User path:
    user_path = "/tmp/vulns/flag_generators_runs/flow-scenario 1-20260212-054712-d36c8a3a89-20260212-054641-568588a508/artifacts/challenge_29d2786be3"
    
    # Current fallback pattern:
    fallback_pattern = f'/tmp/vulns/flag_generators_runs/flow-{scenario_norm}'
    
    print(f"Label: '{scenario_label}'")
    print(f"Norm: '{scenario_norm}'")
    print(f"Fallback Pattern: '{fallback_pattern}'")
    print(f"User Path: '{user_path}'")
    
    if fallback_pattern in user_path:
        print("MATCH! Replacement would work.")
    else:
        print("NO MATCH. Replacement fails.")

    # Discovered dir (hypothetical)
    discovered = "/tmp/vulns/flag_node_generators_runs/cli-scenario_1-NEWUID"
    
    if fallback_pattern in user_path:
        new_path = user_path.replace(fallback_pattern, discovered)
        print(f"New Path: '{new_path}'")

if __name__ == "__main__":
    test_replacement()
