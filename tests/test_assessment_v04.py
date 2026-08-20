from pathlib import Path

from mobileauditkit.assessment import run_assessment
from mobileauditkit.models import AssessmentStatus, AtomicTestResult, EvidenceRecord, StaticAnalysisResult
from mobileauditkit.profile_loader import AssessmentProfile, ProfileModule


def test_static_atomic_results_drive_module_and_masvs_coverage(tmp_path: Path) -> None:
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"fixture")
    profile = AssessmentProfile(name="static-v04", description="fixture", modules={"apk-config": ProfileModule(requires_observation=False)})
    static = StaticAnalysisResult(
        tests=[AtomicTestResult(test_id="MAK-AND-0002", title="cleartext", module="apk-config", engine="static", status=AssessmentStatus.FAIL, observation="cleartext permitted", evaluation="fail", masvs=["MASVS-NETWORK-1"])],
        evidence=[EvidenceRecord(evidence_id="EV-FIXTURE", source="AndroidManifest.xml", module="apk-config", test_id="MAK-AND-0002", evidence_type="manifest", sha256="a" * 64)],
        metadata={"package": "com.example", "apk_sha256": "b" * 64},
    )
    report = run_assessment(package=None, profile=profile, apk_path=apk, apk_inspector=lambda _: static)
    assert report.modules[0].status == AssessmentStatus.FAIL
    assert report.tests[0].test_id == "MAK-AND-0002"
    assert report.masvs_coverage[0].control_id == "MASVS-NETWORK-1"
    assert report.masvs_coverage[0].fail_count == 1
    assert report.metadata["apk_sha256"] == "b" * 64
