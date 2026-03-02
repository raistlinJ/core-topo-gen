import json
import re
import requests
import xml.etree.ElementTree as ET

BASE = 'http://127.0.0.1:9090'
SCENARIO = 'Anatest'
IP_AT_RE = re.compile(r'@\s*((?:\d{1,3}\.){3}\d{1,3})')


def section_item_counts(xml_path: str, scenario: str):
    root = ET.parse(xml_path).getroot()
    scen = None
    for s in root.findall('Scenario'):
        if str(s.get('name') or '').strip().lower() == scenario.lower():
            scen = s
            break
    if scen is None:
        return {}
    editor = scen.find('ScenarioEditor')
    if editor is None:
        return {}
    out = {}
    for sec_name in ('Node Information', 'Routing', 'Vulnerabilities'):
        sec = None
        for x in editor.findall('section'):
            if str(x.get('name') or '').strip() == sec_name:
                sec = x
                break
        out[sec_name] = len(sec.findall('item')) if sec is not None else 0
    return out


s = requests.Session()
s.get(BASE + '/login', timeout=10)
login = s.post(BASE + '/login', data={'username': 'coreadmin', 'password': 'coreadmin'}, allow_redirects=False, timeout=10)
print('login_status', login.status_code)

latest = s.get(BASE + '/api/scenario/latest_xml', params={'scenario': SCENARIO}, timeout=20)
latest_json = latest.json() if latest.ok else {}
xml_path = str(latest_json.get('xml_path') or '').strip()
print('latest_xml', xml_path)
assert xml_path, 'no latest xml found'

before_counts = section_item_counts(xml_path, SCENARIO)
print('before_counts', before_counts)

summary_payload = {
    'project_key_hint': xml_path,
    'scenario_query': SCENARIO,
    'active_index': 0,
    'scenarios': [
        {
            'name': SCENARIO,
            'density_count': 10,
            'scenario_total_nodes': 10,
            'sections': {
                'Node Information': {'density': 0, 'base_nodes': 10, 'additional_nodes': 0, 'combined_nodes': 10, 'items': []},
                'Routing': {'density': 0.5, 'items': []},
                'Services': {'density': 0.5, 'items': []},
                'Traffic': {'density': 0.5, 'items': []},
                'Events': {'density': 0.5, 'items': []},
                'Vulnerabilities': {'density': 0.5, 'items': []},
                'Segmentation': {'density': 0.5, 'items': []},
            },
        }
    ],
}

save = s.post(BASE + '/save_xml_api', data=json.dumps(summary_payload), headers={'Content-Type': 'application/json'}, timeout=30)
print('save_status', save.status_code)
save_json = save.json() if save.headers.get('content-type', '').startswith('application/json') else {}
print('save_ok', save_json.get('ok'))
new_xml = str(save_json.get('result_path') or '').strip()
print('new_xml', new_xml)
assert save_json.get('ok') is True and new_xml, 'save_xml_api failed'

after_counts = section_item_counts(new_xml, SCENARIO)
print('after_counts', after_counts)

topology_persist_ok = True
for key in ('Node Information', 'Routing', 'Vulnerabilities'):
    if before_counts.get(key, 0) > 0 and after_counts.get(key, 0) <= 0:
        topology_persist_ok = False
print('topology_items_persist_ok', topology_persist_ok)

persist = s.post(
    BASE + '/api/plan/persist_flow_plan',
    data=json.dumps({'xml_path': new_xml, 'scenario': SCENARIO}),
    headers={'Content-Type': 'application/json'},
    timeout=120,
)
print('persist_status', persist.status_code)
persist_json = persist.json() if persist.headers.get('content-type', '').startswith('application/json') else {}
print('persist_ok', persist_json.get('ok'))

sequence = s.post(
    BASE + '/api/flag-sequencing/sequence_preview_plan',
    data=json.dumps({'scenario': SCENARIO, 'preview_plan': new_xml, 'length': 3, 'mode': 'preview', 'best_effort': True}),
    headers={'Content-Type': 'application/json'},
    timeout=120,
)
print('sequence_status', sequence.status_code)
sequence_json = sequence.json() if sequence.headers.get('content-type', '').startswith('application/json') else {}
print('sequence_ok', sequence_json.get('ok'), 'flow_valid', sequence_json.get('flow_valid'))

prep = s.post(
    BASE + '/api/flag-sequencing/prepare_preview_for_execute',
    data=json.dumps({'scenario': SCENARIO, 'preview_plan': new_xml, 'length': 3, 'mode': 'preview', 'best_effort': True}),
    headers={'Content-Type': 'application/json'},
    timeout=120,
)
print('prepare_status', prep.status_code)
prep_json = prep.json() if prep.headers.get('content-type', '').startswith('application/json') else {}
print('prepare_ok', prep_json.get('ok'), 'flow_valid', prep_json.get('flow_valid'))

chain = prep_json.get('chain') or []
assignments = prep_json.get('flag_assignments') or []
chain_ip_by_id = {str(n.get('id') or ''): str(n.get('ip4') or '') for n in chain if isinstance(n, dict)}

resolved_ip_mismatches = []
for idx, fa in enumerate(assignments):
    if not isinstance(fa, dict):
        continue
    node_id = str(fa.get('node_id') or '')
    expected = chain_ip_by_id.get(node_id, '')
    ri = fa.get('resolved_inputs') if isinstance(fa.get('resolved_inputs'), dict) else {}
    for key in ('Knowledge(ip)', 'target_ip', 'ip4', 'ipv4'):
        val = str(ri.get(key) or '')
        if val and expected and val != expected:
            resolved_ip_mismatches.append((idx, key, val, expected))

hint_mismatches = []
for idx, fa in enumerate(assignments):
    if not isinstance(fa, dict):
        continue
    next_id = str(fa.get('next_node_id') or '').strip()
    expected_next_ip = chain_ip_by_id.get(next_id, '') if next_id else ''
    hints = []
    if isinstance(fa.get('hint'), str) and fa.get('hint').strip():
        hints.append(fa.get('hint').strip())
    if isinstance(fa.get('hints'), list):
        hints.extend([str(x).strip() for x in fa.get('hints') if isinstance(x, str) and str(x).strip()])
    for text in hints:
        if 'Next' not in text:
            continue
        m = IP_AT_RE.search(text)
        if not m:
            continue
        seen = m.group(1)
        if expected_next_ip and seen != expected_next_ip:
            hint_mismatches.append((idx, seen, expected_next_ip, text))

print('resolved_ip_mismatch_count', len(resolved_ip_mismatches))
if resolved_ip_mismatches:
    print('resolved_ip_mismatch_sample', resolved_ip_mismatches[:5])
print('next_hint_mismatch_count', len(hint_mismatches))
if hint_mismatches:
    print('next_hint_mismatch_sample', hint_mismatches[:5])

print('VERIFY_SUMMARY', json.dumps({
    'topology_items_persist_ok': topology_persist_ok,
    'persist_ok': bool(persist_json.get('ok')),
    'sequence_ok': bool(sequence_json.get('ok')),
    'prepare_ok': bool(prep_json.get('ok')),
    'resolved_ip_mismatch_count': len(resolved_ip_mismatches),
    'next_hint_mismatch_count': len(hint_mismatches),
    'chain_len': len(chain),
    'assignment_len': len(assignments),
}, indent=2))
