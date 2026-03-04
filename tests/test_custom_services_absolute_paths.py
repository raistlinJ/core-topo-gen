from pathlib import Path


def test_coretg_prereqs_service_uses_absolute_paths() -> None:
    p = Path("on_core_machine/custom_services/CoreTGPrereqs.py")
    txt = p.read_text("utf-8", errors="ignore")

    assert 'files: list[str] = ["/runprereqs.sh"]' in txt
    assert 'startup: list[str] = ["/bin/sh /runprereqs.sh"]' in txt
    assert 'LOG="/tmp/coretg_prereqs_output.txt"' in txt


def test_segmentation_service_uses_absolute_paths() -> None:
    p = Path("on_core_machine/custom_services/Segmentation.py")
    txt = p.read_text("utf-8", errors="ignore")

    assert 'files: list[str] = ["/runsegmentation.sh"]' in txt
    assert 'startup: list[str] = ["/bin/bash /runsegmentation.sh &"]' in txt
