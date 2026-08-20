from datetime import UTC, datetime

from mobileauditkit.models import AssessmentReport, CoverageSummary, Finding, Severity
from mobileauditkit.reporting import assessment_to_sarif


def test_sarif_uses_21_schema_and_required_location() -> None:
    finding = Finding(finding_id="MAK-APK-CLEARTEXT", test_id="MAK-AND-0002", title="Manifest explicitly permits cleartext traffic", description="fixture", severity=Severity.HIGH, module="apk-config", masvs=["MASVS-NETWORK-1"], evidence_ids=["EV-123"])
    now = datetime.now(UTC)
    report = AssessmentReport(
        assessment_id="MAK-FIXTURE",
        tool_version="0.4.0",
        profile="static",
        profile_description="fixture",
        started_at=now,
        completed_at=now,
        modules=[],
        coverage=CoverageSummary(total_modules=0, pass_count=0, fail_count=0, inconclusive_count=0, not_tested_count=0, execution_coverage_percent=0, conclusive_coverage_percent=0),
        findings=[finding],
    )
    sarif = assessment_to_sarif(report, default_location="app/src/main/AndroidManifest.xml")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["id"] == "MAK-AND-0002"
    result = run["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/src/main/AndroidManifest.xml"
    assert result["partialFingerprints"]["primaryLocationLineHash"]
