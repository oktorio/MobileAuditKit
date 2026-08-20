from pathlib import Path

from mobileauditkit.assessment import run_assessment
from mobileauditkit.models import AssessmentStatus, Finding, Severity
from mobileauditkit.profile_loader import (
    AssessmentProfile,
    ProfileModule,
    available_profiles,
    load_profile,
)
from mobileauditkit.reporting import write_assessment_json


def test_packaged_profiles_load() -> None:
    assert {"baseline", "runtime", "static"}.issubset(set(available_profiles()))
    profile = load_profile("baseline")
    assert profile.modules["network"].fail_threshold == Severity.HIGH


def test_assessment_pass_fail_and_coverage() -> None:
    profile = AssessmentProfile(
        name="test",
        description="fixture",
        modules={
            "network": ProfileModule(fail_threshold=Severity.HIGH),
            "crypto": ProfileModule(fail_threshold=Severity.HIGH),
        },
    )

    def observer(package: str, module: str, seconds: float, *, spawn: bool = False):
        if module == "network":
            return [{"event": "network_cleartext"}]
        return [{"event": "crypto_algorithm", "algorithm": "AES/GCM/NoPadding"}]

    report = run_assessment(package="com.example", profile=profile, observer=observer)
    statuses = {item.module: item.status for item in report.modules}
    assert statuses == {"network": AssessmentStatus.FAIL, "crypto": AssessmentStatus.PASS}
    assert report.coverage.execution_coverage_percent == 100.0
    assert report.coverage.conclusive_coverage_percent == 100.0


def test_no_runtime_evidence_is_inconclusive() -> None:
    profile = AssessmentProfile(
        name="test",
        description="fixture",
        modules={"network": ProfileModule(fail_threshold=Severity.HIGH)},
    )
    report = run_assessment(
        package="com.example",
        profile=profile,
        observer=lambda *args, **kwargs: [],
    )
    assert report.modules[0].status == AssessmentStatus.INCONCLUSIVE


def test_missing_static_input_is_not_tested() -> None:
    profile = AssessmentProfile(
        name="test",
        description="fixture",
        modules={"apk-config": ProfileModule(fail_threshold=Severity.MEDIUM)},
    )
    report = run_assessment(package=None, profile=profile)
    assert report.modules[0].status == AssessmentStatus.NOT_TESTED
    assert report.coverage.execution_coverage_percent == 0.0


def test_module_error_is_inconclusive_and_does_not_abort() -> None:
    profile = AssessmentProfile(
        name="test",
        description="fixture",
        modules={
            "network": ProfileModule(fail_threshold=Severity.HIGH),
            "crypto": ProfileModule(fail_threshold=Severity.HIGH),
        },
    )

    def observer(package: str, module: str, seconds: float, *, spawn: bool = False):
        if module == "network":
            raise RuntimeError("device disconnected")
        return [{"event": "crypto_algorithm", "algorithm": "AES/GCM/NoPadding"}]

    report = run_assessment(package="com.example", profile=profile, observer=observer)
    statuses = {item.module: item.status for item in report.modules}
    assert statuses["network"] == AssessmentStatus.INCONCLUSIVE
    assert statuses["crypto"] == AssessmentStatus.PASS


def test_static_findings_use_profile_threshold(tmp_path: Path) -> None:
    profile = AssessmentProfile(
        name="static-test",
        description="fixture",
        modules={"apk-config": ProfileModule(fail_threshold=Severity.MEDIUM)},
    )
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"placeholder")

    def inspector(path: Path):
        return [
            Finding(
                finding_id="MAK-APK-DEBUGGABLE",
                title="debuggable",
                description="fixture",
                severity=Severity.HIGH,
                module="apk-config",
                evidence={"debuggable": True},
            )
        ]

    report = run_assessment(package=None, profile=profile, apk_path=apk, apk_inspector=inspector)
    assert report.modules[0].status == AssessmentStatus.FAIL


def test_consolidated_json_redacts_evidence(tmp_path: Path) -> None:
    profile = AssessmentProfile(
        name="test",
        description="fixture",
        modules={"network": ProfileModule(fail_threshold=Severity.HIGH)},
    )

    def observer(*args, **kwargs):
        return [{"event": "network_tls_context", "password": "secret-value"}]

    report = run_assessment(package="com.example", profile=profile, observer=observer)
    output = write_assessment_json(report, tmp_path / "assessment.json")
    text = output.read_text(encoding="utf-8")
    assert "secret-value" not in text
    assert "[REDACTED]" in text
