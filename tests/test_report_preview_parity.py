from core_topo_gen.utils.report import write_report


def test_report_includes_preview_parity_when_present(tmp_path):
    out = tmp_path / "rep.md"
    write_report(
        out_path=str(out),
        scenario_name="scen",
        routers=[],
        hosts=[],
        switches=[],
        router_protocols={},
        service_assignments={},
        metadata={"preview_attached": True, "preview_realized": True},
    )

    txt = out.read_text(encoding="utf-8")
    assert "Preview parity: attached=True realized=True" in txt
