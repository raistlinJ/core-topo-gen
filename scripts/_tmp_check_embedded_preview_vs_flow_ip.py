import requests
from webapp import app_backend as backend

BASE='http://127.0.0.1:9090'
SCEN='Anatest'

s=requests.Session(); s.get(BASE+'/login',timeout=10); s.post(BASE+'/login',data={'username':'coreadmin','password':'coreadmin'},allow_redirects=False,timeout=10)
xml=s.get(BASE+'/api/scenario/latest_xml',params={'scenario':SCEN},timeout=20).json().get('xml_path','')
af=s.get(BASE+'/api/flag-sequencing/attackflow_preview',params={'scenario':SCEN,'xml_path':xml,'prefer_flow':1,'best_effort':1},timeout=60).json()
payload=backend._load_preview_payload_from_path(xml, SCEN)
preview=(payload.get('full_preview') if isinstance(payload,dict) else {}) or {}
hosts=(preview.get('hosts') if isinstance(preview,dict) else []) or []
ip_by_id={str((h or {}).get('node_id') or (h or {}).get('id') or ''): backend._first_valid_ipv4((h or {}).get('ip4') or (h or {}).get('ipv4') or (h or {}).get('ip') or '') for h in hosts if isinstance(h,dict)}
m=[]
for n in (af.get('chain') or []):
    nid=str((n or {}).get('id') or '').strip(); cip=backend._first_valid_ipv4((n or {}).get('ip4') or '')
    exp=ip_by_id.get(nid,'')
    if nid and exp and cip and cip!=exp:
        m.append((nid,cip,exp))
print('chain_len',len(af.get('chain') or []),'mismatch_count',len(m))
print('sample',m[:5])
