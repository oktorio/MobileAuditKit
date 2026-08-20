from mobileauditkit.event_parser import finding_from_event
from mobileauditkit.models import Severity


def test_cleartext_event_is_high() -> None:
    event = {"event": "network_cleartext", "origin": {"scheme": "http", "host": "example.test"}}
    finding = finding_from_event("network", event, "com.example")
    assert finding.severity == Severity.HIGH
    assert "MASWE-0050" in finding.maswe


def test_biometric_without_crypto_is_medium() -> None:
    finding = finding_from_event(
        "authentication", {"event": "biometric_authentication", "crypto_bound": False}
    )
    assert finding.severity == Severity.MEDIUM
    assert "MASTG-TEST-0327" in finding.mastg


def test_resilience_is_observation_not_bypass() -> None:
    finding = finding_from_event(
        "resilience", {"event": "resilience_root_check", "result_modified": False}
    )
    assert finding.severity == Severity.INFO
    assert finding.evidence["result_modified"] is False
