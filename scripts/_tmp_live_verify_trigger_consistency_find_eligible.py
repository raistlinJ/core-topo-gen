import os
import json
import re
from pathlib import Path
import xml.etree.ElementTree as ET
import requests

BASE = 'http://127.0.0.1:9090'
IP_AT_RE = re.compile(r'@\s*((?:\d{1,3}\.){3}\d{1,3})')


def scenarios_in_xml(path: Path):
    out = []
    try:
        root = ET.parse(path).getroot()
        for scen in root.findall('Scenario'):
            name = str(scen.get('name') or '').strip()
            if name:
                out.append(name)
    except Exception:
        return []
    return out


def recent_xmls(limit=25):
    base = Path('outputs')
    paths = []
    if not base.exists():
        return []
    for p in base.glob('scenarios-*/**/*.xml'):
        try:
            paths.append((p.stat().st_mtime, p))
        except Exception:
            continue
    paths.sort(key=lambda t: t[0], reverse=True)
    return [p for _, p in paths[:limit]]


s = requests.Session()
s.get(BASE + '/login', timeout=10)
s.post(BASE + '/login', data={'username': 'coreadmin', 'password': 'coreadmin'}, allow_redirects=False, timeout=10)

candidates = []
for xml in recent_xmls(30):
    for scen in scenarios_in_xml(xml):
        candidates.append((str(xml.resolve()), scen))

seen = set()
ordered = []
for x in candidates:
    if x in seen:
        continue
    seen.add(x)
    ordered.append(x)

print('candidate_pairs', len(ordered))

for xml_path, scenario in ordered:
    print('\nTRY', scenario, xml_path)
    try:
        persist = s.post(BASE + '/api/plan/persist_flow_plan', json={'xml_path': xml_path, 'scenario': scenario}, timeout=120)
        if persist.status_code != 200 or not (persist.json() or {}).get('ok'):
            print('  persist_fail', persist.status_code)
            continue

        seq = s.post(
            BASE + '/api/flag-sequencing/sequence_preview_plan',
            json={'scenario': scenario, 'preview_plan': xml_path, 'length': 3, 'best_effort': True, 'allow_node_duplicates': True},
            timeout=120,
        )
        seqj = seq.json() if seq.headers.get('content-type', '').startswith('application/json') else {}
        if seq.status_code != 200 or not seqj.get('ok'):
            print('  sequence_fail', seq.status_code, seqj.get('error'))
            continue

        prep = s.post(
            BASE + '/api/flag-sequencing/prepare_preview_for_execute',
            json={'scenario': scenario, 'preview_plan': xml_path, 'length': 3, 'mode': 'preview', 'best_effort': True, 'allow_node_duplicates': True},
            timeout=180,
        )
        prepj = prep.json() if prep.headers.get('content-type', '').startswith('application/json') else {}
        if prep.status_code != 200 or not prepj.get('ok'):
            print('  prepare_fail', prep.status_code, prepj.get('error'))
            continue

        chain = prepj.get('chain') or []
        assigns = prepj.get('flag_assignments') or []
        ip_by_id = {str(n.get('id') or ''): str(n.get('ip4') or '') for n in chain if isinstance(n, dict)}

        res_m = []
        hint_m = []
        for idx, a in enumerate(assigns):
            if not isinstance(a, dict):
                continue
            nid = str(a.get('node_id') or '')
            expected = ip_by_id.get(nid, '')
            ri = a.get('resolved_inputs') if isinstance(a.get('resolved_inputs'), dict) else {}
            for key in ('Knowledge(ip)', 'target_ip', 'ip4', 'ipv4'):
                val = str(ri.get(key) or '')
                if val and expected and val != expected:
                    res_m.append((idx, key, val, expected))

            next_id = str(a.get('next_node_id') or '').strip()
            expected_next = ip_by_id.get(next_id, '') if next_id else ''
            hints = []
            if isinstance(a.get('hint'), str) and a.get('hint').strip():
                hints.append(a.get('hint').strip())
            if isinstance(a.get('hints'), list):
                hints.extend([str(x).strip() for x in a.get('hints') if isinstance(x, str) and str(x).strip()])
            for text in hints:
                if 'Next' not in text:
                    continue
                m = IP_AT_RE.search(text)
                if m and expected_next and m.group(1) != expected_next:
                    hint_m.append((idx, m.group(1), expected_next, text))

        print('  SUCCESS scenario=', scenario)
        print('  chain_len=', len(chain), 'assign_len=', len(assigns))
        print('  resolved_ip_mismatch_count=', len(res_m))
        print('  next_hint_mismatch_count=', len(hint_m))
        if hint_m:
            print('  hint_mismatch_sample=', hint_m[:3])

        print('VERIFY_SUMMARY', json.dumps({
            'scenario': scenario,
            'xml_path': xml_path,
            'prepare_ok': True,
            'chain_len': len(chain),
            'assignment_len': len(assigns),
            'resolved_ip_mismatch_count': len(res_m),
            'next_hint_mismatch_count': len(hint_m),
        }, indent=2))
        break
    except Exception as exc:
        print('  error', exc)
        continue
else:
    print('VERIFY_SUMMARY', json.dumps({'prepare_ok': False, 'reason': 'no eligible scenario found in recent outputs'}, indent=2))
