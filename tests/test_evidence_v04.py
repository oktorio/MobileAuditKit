from mobileauditkit.evidence import make_evidence


def test_evidence_id_and_hash_are_deterministic_and_redacted() -> None:
    first = make_evidence(
        source="fixture",
        module="network",
        test_id="MAK-DYN-0221",
        evidence_type="runtime-event",
        data={"event": "network_tls_context", "password": "do-not-store"},
    )
    second = make_evidence(
        source="fixture",
        module="network",
        test_id="MAK-DYN-0221",
        evidence_type="runtime-event",
        data={"event": "network_tls_context", "password": "do-not-store"},
    )
    assert first.evidence_id == second.evidence_id
    assert first.sha256 == second.sha256
    assert first.data["password"] == "[REDACTED]"
