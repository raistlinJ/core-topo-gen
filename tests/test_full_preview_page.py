import json
import os
import re
from pathlib import Path

from webapp.app_backend import app


FULL_PREVIEW_SCRIPTS_PATH = Path(__file__).resolve().parent.parent / 'webapp' / 'templates' / 'full_preview_scripts.html'


def _sample_xml_path() -> str:
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.abspath(os.path.join(here, os.pardir, 'sample.xml'))


def test_full_preview_page_matches_modal_preview():
    app.config['TESTING'] = True
    client = app.test_client()

    sample_xml = _sample_xml_path()
    assert os.path.exists(sample_xml), f"sample xml missing at {sample_xml}"

    # Authenticate with default seeded admin user for protected routes
    login_resp = client.post('/login', data={'username': 'coreadmin', 'password': 'coreadmin'})
    assert login_resp.status_code in (302, 303)

    api_resp = client.post('/api/plan/preview_full', json={'xml_path': sample_xml})
    assert api_resp.status_code == 200
    api_payload = api_resp.get_json()
    assert api_payload and api_payload.get('ok'), f"API payload error: {api_payload}"

    api_preview = api_payload['full_preview']
    seed = api_preview.get('seed') or ''

    page_resp = client.post('/plan/full_preview_page', data={'xml_path': sample_xml, 'seed': seed})
    assert page_resp.status_code == 200

    html = page_resp.data.decode('utf-8')
    match = re.search(r'<script id="fpDataJson" type="application/json">(.*?)</script>', html, re.S)
    assert match, 'embedded preview JSON not found in full preview page'

    page_preview = json.loads(match.group(1))

    # Ensure core metrics and detailed structures match between modal and standalone previews
    assert page_preview.get('seed') == api_preview.get('seed')
    for key in (
        'routers',
        'hosts',
        'switches_detail',
        'services_preview',
        'vulnerabilities_preview',
        'segmentation_preview',
        'traffic_summary',
        'r2r_edges_preview',
        'host_router_map',
        'layout_positions',
    ):
        assert page_preview.get(key) == api_preview.get(key), f"Mismatch for key '{key}'"


def test_full_preview_scripts_support_duplicate_sequence_nodes() -> None:
    text = FULL_PREVIEW_SCRIPTS_PATH.read_text(encoding='utf-8', errors='ignore')

    expected_snippets = [
        'function sequenceIndices(node) {',
        'function sequenceOccurrencesForNode(node, flow) {',
        'const faByIndex = Array.isArray(fas) ? fas : [];',
        'const indexAssignment = (idx < faByIndex.length && faByIndex[idx] && typeof faByIndex[idx] === \'object\')',
        'target.sequence_indices = Array.from(new Set([...',
        'const seqLabel = sequenceRomanLabel(d);',
        '.text(d => sequenceRomanLabel(d));',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, 'Missing duplicate-sequence preview handling snippets: ' + '; '.join(missing)
