import json
from pathlib import Path

from mobileauditkit.models import Finding, Severity
from mobileauditkit.reporting import write_html_report, write_json_report


def test_reports_redact_sensitive_evidence(tmp_path: Path) -> None:
    finding = Finding(
        finding_id="MAK-T-1",
        title="Example",
        description="Example",
        severity=Severity.INFO,
        evidence={"token": "sensitive-value", "safe": "ok"},
    )
    json_path = write_json_report([finding], tmp_path / "report.json")
    html_path = write_html_report([finding], tmp_path / "report.html")
    payload = json.loads(json_path.read_text())
    assert payload["findings"][0]["evidence"]["token"] == "[REDACTED]"
    assert "sensitive-value" not in html_path.read_text()
