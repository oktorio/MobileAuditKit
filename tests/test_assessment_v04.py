from pathlib import Path

from mobileauditkit.assessment import run_assessment
from mobileauditkit.models import (
    AssessmentStatus,
    AtomicTestResult,
    EvidenceRecord,
    StaticAnalysisResult,
)
from mobileauditkit.profile_loader import AssessmentProfile, ProfileModule
from mobileauditkit.test_registry import tests_for_module


def test_static_atomic_results_drive_module_and_masvs_coverage(tmp_path: Path) -> None:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"fixture")
    profile = AssessmentProfile(
        name="static-v04",
        description="fixture",
        modules={"apk-config": ProfileModule(requires_observation=False)},
    )
    static = StaticAnalysisResult(
        tests=[
            AtomicTestResult(
                test_id="MAK-AND-0002",
                title="cleartext",
                module="apk-config",
                engine="static",
                status=AssessmentStatus.FAIL,
                observation="cleartext permitted",
                evaluation="fail",
                masvs=["MASVS-NETWORK-1"],
            )
        ],
        evidence=[
            EvidenceRecord(
                evidence_id="EV-FIXTURE",
                source="AndroidManifest.xml",
                module="apk-config",
                test_id="MAK-AND-0002",
                evidence_type="manifest",
                sha256="a" * 64,
            )
        ],
        metadata={"package": "com.example", "apk_sha256": "b" * 64},
    )
    report = run_assessment(
        package=None,
        profile=profile,
        apk_path=apk,
        apk_inspector=lambda _: static,
    )
    expected = {item.test_id for item in tests_for_module("apk-config", engine="static")}
    assert report.modules[0].status == AssessmentStatus.FAIL
    assert {item.test_id for item in report.tests} == expected
    cleartext = next(item for item in report.tests if item.test_id == "MAK-AND-0002")
    assert cleartext.status == AssessmentStatus.FAIL
    network_coverage = next(
        item for item in report.masvs_coverage if item.control_id == "MASVS-NETWORK-1"
    )
    assert network_coverage.fail_count == 1
    assert report.metadata["apk_sha256"] == "b" * 64


def test_missing_static_input_marks_every_registry_test_not_tested() -> None:
    profile = AssessmentProfile(
        name="static-missing",
        description="fixture",
        modules={"apk-config": ProfileModule(requires_observation=False)},
    )
    report = run_assessment(package=None, profile=profile)
    expected = {item.test_id for item in tests_for_module("apk-config", engine="static")}
    static_results = [item for item in report.tests if item.module == "apk-config"]
    assert report.modules[0].status == AssessmentStatus.NOT_TESTED
    assert {item.test_id for item in static_results} == expected
    assert all(item.status == AssessmentStatus.NOT_TESTED for item in static_results)
    assert report.masvs_coverage
    assert all(
        item.not_tested_count == item.total_tests for item in report.masvs_coverage
    )


def test_missing_dynamic_package_marks_atomic_test_not_tested() -> None:
    profile = AssessmentProfile(
        name="runtime-missing",
        description="fixture",
        modules={"network": ProfileModule(fail_threshold="HIGH")},
    )
    report = run_assessment(package=None, profile=profile)
    network_results = [item for item in report.tests if item.module == "network"]
    expected = {item.test_id for item in tests_for_module("network", engine="dynamic")}
    assert report.modules[0].status == AssessmentStatus.NOT_TESTED
    assert {item.test_id for item in network_results} == expected
    assert all(item.status == AssessmentStatus.NOT_TESTED for item in network_results)


def test_static_module_error_marks_every_registry_test_inconclusive(tmp_path: Path) -> None:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"fixture")
    profile = AssessmentProfile(
        name="static-error",
        description="fixture",
        modules={"apk-config": ProfileModule(requires_observation=False)},
    )

    def broken_inspector(_: Path) -> StaticAnalysisResult:
        raise RuntimeError("fixture failure")

    report = run_assessment(
        package=None,
        profile=profile,
        apk_path=apk,
        apk_inspector=broken_inspector,
    )
    expected = {item.test_id for item in tests_for_module("apk-config", engine="static")}
    static_results = [item for item in report.tests if item.module == "apk-config"]
    assert report.modules[0].status == AssessmentStatus.INCONCLUSIVE
    assert {item.test_id for item in static_results} == expected
    assert all(item.status == AssessmentStatus.INCONCLUSIVE for item in static_results)
