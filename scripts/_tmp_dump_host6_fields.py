import requests, json
BASE='http://127.0.0.1:9090'; SCEN='Anatest'
s=requests.Session(); s.get(BASE+'/login',timeout=10); s.post(BASE+'/login',data={'username':'coreadmin','password':'coreadmin'},allow_redirects=False,timeout=10)
xml=s.get(BASE+'/api/scenario/latest_xml',params={'scenario':SCEN},timeout=20).json().get('xml_path','')
pf=s.post(BASE+'/api/plan/preview_full',json={'scenario':SCEN,'xml_path':xml},timeout=60).json()
hosts=((pf.get('full_preview') or {}).get('hosts') or [])
for h in hosts:
    if str(h.get('node_id') or '')=='6':
        print(json.dumps(h, indent=2))
        break
