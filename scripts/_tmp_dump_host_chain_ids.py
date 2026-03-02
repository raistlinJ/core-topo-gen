import requests

BASE='http://127.0.0.1:9090'
SCEN='Anatest'
s=requests.Session(); s.get(BASE+'/login',timeout=10); s.post(BASE+'/login',data={'username':'coreadmin','password':'coreadmin'},allow_redirects=False,timeout=10)
xml=s.get(BASE+'/api/scenario/latest_xml',params={'scenario':SCEN},timeout=20).json().get('xml_path','')
pf=s.post(BASE+'/api/plan/preview_full',json={'scenario':SCEN,'xml_path':xml},timeout=60).json()
af=s.get(BASE+'/api/flag-sequencing/attackflow_preview',params={'scenario':SCEN,'xml_path':xml,'prefer_flow':1,'best_effort':1},timeout=60).json()
print('latest_xml', xml)
print('attack_preview_plan_path', af.get('preview_plan_path'))
hosts=((pf.get('full_preview') or {}).get('hosts') or [])
print('host_ids_sample',[(str(h.get('node_id') or h.get('id') or ''),str(h.get('name') or ''),str(h.get('ip4') or '')) for h in hosts[:12]])
chain=(af.get('chain') or [])
print('chain_ids',[(str(n.get('id') or ''),str(n.get('name') or ''),str(n.get('ip4') or '')) for n in chain])
