import re
import requests

BASE='http://127.0.0.1:9090'
SCEN='Anatest'

s=requests.Session(); s.get(BASE+'/login',timeout=10); s.post(BASE+'/login',data={'username':'coreadmin','password':'coreadmin'},allow_redirects=False,timeout=10)
xml=s.get(BASE+'/api/scenario/latest_xml',params={'scenario':SCEN},timeout=20).json().get('xml_path','')
html=s.post(BASE+'/plan/full_preview_from_xml',data={'xml_path':xml,'scenario':SCEN,'embed':'1'},timeout=60).text
af=s.get(BASE+'/api/flag-sequencing/attackflow_preview',params={'scenario':SCEN,'xml_path':xml,'prefer_flow':1,'best_effort':1},timeout=60).json()

# parse Hosts table rows: ID, Name, Role, IP, Router, Vulns
rows=re.findall(
    r'<tr>\s*<td>([^<]+)</td>\s*<td>([^<]+)</td>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*</tr>',
    html,
    flags=re.I,
)
preview_ip_by_name={name.strip(): ip.strip().split('/',1)[0] for (_id, name, _role, ip, _router, _vuln) in rows if name.strip() and ip.strip()}

m=[]
for n in (af.get('chain') or []):
    name=str((n or {}).get('name') or '').strip(); cip=str((n or {}).get('ip4') or '').split('/',1)[0].strip(); exp=preview_ip_by_name.get(name,'')
    if name and exp and cip and cip!=exp:
        m.append((name,cip,exp))

print('preview_rows',len(preview_ip_by_name),'chain_len',len(af.get('chain') or []),'mismatch_count',len(m))
print('sample',m[:5])
