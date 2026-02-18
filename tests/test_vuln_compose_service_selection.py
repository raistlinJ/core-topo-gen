import yaml

from core_topo_gen.utils import vuln_process


def test_select_service_key_prefers_webserver_over_infra_for_airflow_cve():
    """Regression: Airflow CVE compose lists postgres/redis before airflow-webserver.

    When prefer_service doesn't match any service key, we should still pick a likely
    interactive app service (airflow-webserver) so CORE starts the expected service.
    """

    compose_path = (
        "outputs/installed_vuln_catalogs/20260115-183504-10474c/content/vulhub/"
        "airflow/CVE-2020-11981/docker-compose.yml"
    )
    with open(compose_path, "r", encoding="utf-8") as f:
        compose_obj = yaml.safe_load(f)

    selected = vuln_process._select_service_key(compose_obj, prefer_service="airflow/CVE-2020-11981")
    assert selected == "airflow-webserver"
