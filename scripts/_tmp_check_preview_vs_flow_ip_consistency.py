import requests

BASE = 'http://127.0.0.1:9090'
SCENARIO = 'Anatest'

s = requests.Session()
s.get(BASE + '/login', timeout=10)
s.post(BASE + '/login', data={'username': 'coreadmin', 'password': 'coreadmin'}, allow_redirects=False, timeout=10)

latest = s.get(BASE + '/api/scenario/latest_xml', params={'scenario': SCENARIO}, timeout=20).json()
xml_path = latest.get('xml_path', '')

preview_resp = s.post(BASE + '/api/plan/preview_full', json={'scenario': SCENARIO, 'xml_path': xml_path}, timeout=60)
preview = preview_resp.json() if preview_resp.headers.get('content-type', '').startswith('application/json') else {}
attack = s.get(
    BASE + '/api/flag-sequencing/attackflow_preview',
    params={'scenario': SCENARIO, 'xml_path': xml_path, 'prefer_flow': 1, 'best_effort': 1},
    timeout=60,
).json()

hosts = ((preview.get('full_preview') or {}).get('hosts') or [])
ip_by_id = {}
for host in hosts:
    if not isinstance(host, dict):
        continue
    node_id = str(host.get('node_id') or host.get('id') or '').strip()
    if not node_id:
        continue
    ip = str(host.get('ip4') or host.get('ipv4') or host.get('ip') or '').split('/', 1)[0].strip()
    if ip:
        ip_by_id[node_id] = ip

mismatches = []
for node in (attack.get('chain') or []):
    if not isinstance(node, dict):
        continue
    node_id = str(node.get('id') or '').strip()
    chain_ip = str(node.get('ip4') or '').split('/', 1)[0].strip()
    expected = ip_by_id.get(node_id, '')
    if node_id and expected and chain_ip and chain_ip != expected:
        mismatches.append((node_id, chain_ip, expected))

print('preview_ok', bool(preview.get('ok')), 'attack_ok', bool(attack.get('ok')))
print('chain_len', len(attack.get('chain') or []))
print('mismatch_count', len(mismatches))
if mismatches:
    print('mismatch_sample', mismatches[:5])
