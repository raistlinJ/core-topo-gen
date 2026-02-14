from pathlib import Path
import re


TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "webapp" / "templates"


def _iter_template_files():
    return sorted(TEMPLATES_DIR.rglob("*.html"))


def test_templates_do_not_link_to_bare_scenarios_route():
    # Bare /scenarios is not a valid route in this app and causes a 404.
    # Allow only scoped subroutes such as /scenarios/preview and
    # /scenarios/flag-sequencing.
    forbidden = re.compile(r"['\"]\/scenarios(?:\?|['\"])")

    offenders: list[str] = []
    for path in _iter_template_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        if forbidden.search(text):
            offenders.append(str(path.relative_to(TEMPLATES_DIR.parent.parent)))

    assert not offenders, (
        "Found forbidden bare '/scenarios' navigation target(s): "
        + ", ".join(offenders)
    )
