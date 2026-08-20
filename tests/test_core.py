from mobileauditkit.models import Confidence, Finding, Severity
from mobileauditkit.redaction import redact, redact_text


def test_redacts_sensitive_dictionary_keys() -> None:
    result = redact({"username": "alice", "password": "secret", "token": "abc123456789"})
    assert result["username"] == "alice"
    assert result["password"] == "[REDACTED]"
    assert result["token"] == "[REDACTED]"


def test_redacts_bearer_token_in_text() -> None:
    result = redact_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456")
    assert "abcdefghijklmnopqrstuvwxyz" not in result
    assert "[REDACTED_TOKEN]" in result


def test_finding_defaults_to_observed() -> None:
    finding = Finding(finding_id="MAK-TEST-001", title="Example", description="fixture", severity=Severity.INFO)
    assert finding.confidence == Confidence.OBSERVED
    assert finding.evidence == {}
