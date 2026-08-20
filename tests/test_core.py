from mobileauditkit.models import Confidence, Finding, Severity
from mobileauditkit.redaction import redact, redact_text


def test_redacts_sensitive_dictionary_keys() -> None:
    source = {"username": "alice", "password": "secret", "token": "abc123456789"}
    result = redact(source)
    assert result["username"] == "alice"
    assert result["password"] == "[REDACTED]"
    assert result["token"] == "[REDACTED]"


def test_redacts_bearer_token_in_text() -> None:
    value = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"
    result = redact_text(value)
    assert "abcdefghijklmnopqrstuvwxyz" not in result
    assert "[REDACTED_TOKEN]" in result


def test_finding_defaults_to_observed() -> None:
    finding = Finding(
        finding_id="MAK-TEST-001",
        title="Example observation",
        description="Test fixture",
        severity=Severity.INFO,
    )
    assert finding.confidence == Confidence.OBSERVED
    assert finding.evidence == {}
