from core_topo_gen.utils.vuln_process import load_vuln_catalog, resolve_vulnerability_catalog_entry


def test_load_vuln_catalog_prefers_active_catalog_identity_over_repo_default(tmp_path):
    active_dir = tmp_path / 'outputs' / 'installed_vuln_catalogs' / 'active-cat'
    active_dir.mkdir(parents=True, exist_ok=True)
    active_csv = active_dir / 'vuln_list_w_url.csv'
    active_csv.write_text(
        'Name,Path,Type,Vector,Startup,CVE,Description,References\n'
        f'jboss/CVE-2017-12149,{tmp_path}/content/vulhub/jboss/CVE-2017-12149/docker-compose.yml,docker-compose,,,CVE-2017-12149,,\n',
        encoding='utf-8',
    )

    state_path = tmp_path / 'outputs' / 'installed_vuln_catalogs' / '_catalogs_state.json'
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        '{"active_id":"active-cat","catalogs":[{"id":"active-cat","csv_paths":["outputs/installed_vuln_catalogs/active-cat/vuln_list_w_url.csv"]}]}',
        encoding='utf-8',
    )

    raw_dir = tmp_path / 'raw_datasources'
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / 'vuln_list_w_url.csv').write_text(
        'Name,Path,Type,Vector,Startup,CVE,Description,References\n'
        'jboss,https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149,docker-compose,,,CVE-2017-12149,,\n',
        encoding='utf-8',
    )

    items = load_vuln_catalog(str(tmp_path))
    assert len(items) == 1
    assert items[0]['Name'] == 'jboss/CVE-2017-12149'
    assert items[0]['Path'].endswith('/content/vulhub/jboss/CVE-2017-12149/docker-compose.yml')


def test_resolve_vulnerability_catalog_entry_matches_url_to_installed_catalog_path():
    catalog = [{
        'Name': 'jboss/CVE-2017-12149',
        'Path': '/tmp/content/vulhub/jboss/CVE-2017-12149/docker-compose.yml',
        'CVE': 'CVE-2017-12149',
    }]

    resolved = resolve_vulnerability_catalog_entry(
        catalog,
        v_name='jboss',
        v_path='https://github.com/vulhub/vulhub/tree/master/jboss/CVE-2017-12149',
    )

    assert resolved == {
        'name': 'jboss/CVE-2017-12149',
        'path': '/tmp/content/vulhub/jboss/CVE-2017-12149/docker-compose.yml',
    }