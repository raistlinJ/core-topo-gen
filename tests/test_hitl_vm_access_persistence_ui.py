from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_merge_persisted_hitl_state_ignores_empty_payloads() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const sourceHitlRaw = (persistedClone.hitl && typeof persistedClone.hitl === 'object') ? persistedClone.hitl : null;",
        "const hasCorePayload = !!(sourceCoreRaw && Object.values(sourceCoreRaw).some((entry) => hasMeaningfulValue(entry)));",
        "if (!(hasCorePayload || hasProxPayload || hasInterfacesPayload || hasParticipantPayload || hasEnabledPayload)) {",
        "if (hasCorePayload && sourceHitl.core && typeof sourceHitl.core === 'object') {",
        "if (hasProxPayload && sourceHitl.proxmox && typeof sourceHitl.proxmox === 'object') {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing guarded HITL merge snippets for VM/Access persistence: " + "; ".join(missing)
