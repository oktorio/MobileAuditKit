from mobileauditkit.assessment import run_assessment
from mobileauditkit.models import (
    AssessmentStatus,
    DynamicSessionResult,
    FlowMarker,
    HookHealth,
    HookHealthState,
    RuntimeFingerprint,
    Severity,
)
from mobileauditkit.profile_loader import AssessmentProfile, ProfileModule


def ready(module: str, count: int = 1) -> HookHealth:
    return HookHealth(
        module=module,
        state=HookHealthState.READY,
        script_loaded=True,
        signal_received=True,
        hooks_attempted=2,
        hooks_installed=2,
        security_event_count=count,
    )


def test_default_scan_uses_single_session_for_all_dynamic_modules() -> None:
    profile = AssessmentProfile(
        name="runtime-two",
        description="fixture",
        modules={
            "network": ProfileModule(fail_threshold=Severity.HIGH),
            "crypto": ProfileModule(fail_threshold=Severity.HIGH),
        },
    )
    calls = []

    def session_runner(package, modules, seconds, *, spawn=False, flow="default"):
        calls.append((package, modules, seconds, spawn, flow))
        return DynamicSessionResult(
            package=package,
            modules=modules,
            events={
                "network": [{"event": "network_cleartext", "flow": flow}],
                "crypto": [
                    {
                        "event": "crypto_algorithm",
                        "algorithm": "AES/GCM/NoPadding",
                        "flow": flow,
                    }
                ],
            },
            hook_health={"network": ready("network"), "crypto": ready("crypto")},
            fingerprint=RuntimeFingerprint(fingerprint_id="FP-FIX", package=package),
            flows=[
                FlowMarker(marker_id="FLOW-1", flow=flow, phase="start"),
                FlowMarker(marker_id="FLOW-2", flow=flow, phase="end"),
            ],
            duration_seconds=5.0,
        )

    report = run_assessment(
        package="com.example",
        profile=profile,
        seconds=5,
        flow="login",
        session_runner=session_runner,
    )
    assert len(calls) == 1
    assert calls[0][1] == ["network", "crypto"]
    statuses = {item.module: item.status for item in report.modules}
    assert statuses == {
        "network": AssessmentStatus.FAIL,
        "crypto": AssessmentStatus.PASS,
    }
    assert report.runtime_fingerprint
    assert report.runtime_fingerprint.fingerprint_id == "FP-FIX"
    assert [marker.phase for marker in report.flows] == ["start", "end"]
    assert any(item.evidence_type == "runtime-fingerprint" for item in report.evidence)
    assert sum(item.evidence_type == "flow-marker" for item in report.evidence) == 2


def test_custom_observer_api_remains_compatible() -> None:
    profile = AssessmentProfile(
        name="legacy",
        description="fixture",
        modules={
            "network": ProfileModule(fail_threshold=Severity.HIGH),
            "crypto": ProfileModule(fail_threshold=Severity.HIGH),
        },
    )
    calls = []

    def observer(package, module, seconds, *, spawn=False):
        calls.append(module)
        if module == "network":
            return [{"event": "network_cleartext"}]
        return [{"event": "crypto_algorithm", "algorithm": "AES/GCM/NoPadding"}]

    report = run_assessment(package="com.example", profile=profile, observer=observer)
    assert calls == ["network", "crypto"]
    statuses = {item.module: item.status for item in report.modules}
    assert statuses == {
        "network": AssessmentStatus.FAIL,
        "crypto": AssessmentStatus.PASS,
    }
    assert report.metadata["dynamic_orchestrator"] == "legacy/custom-observer"


def test_contextual_finding_does_not_override_atomic_inconclusive() -> None:
    profile = AssessmentProfile(
        name="auth",
        description="fixture",
        modules={"authentication": ProfileModule(fail_threshold=Severity.MEDIUM)},
    )

    def observer(*args, **kwargs):
        return [{"event": "biometric_authentication", "crypto_bound": False}]

    report = run_assessment(package="com.example", profile=profile, observer=observer)
    assert report.findings[0].severity == Severity.MEDIUM
    assert report.findings[0].test_id == "MAK-DYN-0230"
    assert report.tests[0].status == AssessmentStatus.INCONCLUSIVE
    assert report.modules[0].status == AssessmentStatus.INCONCLUSIVE


def test_missing_package_marks_all_dynamic_atomic_tests_not_tested() -> None:
    profile = AssessmentProfile(
        name="network",
        description="fixture",
        modules={"network": ProfileModule(fail_threshold=Severity.HIGH)},
    )
    report = run_assessment(package=None, profile=profile)
    assert report.modules[0].status == AssessmentStatus.NOT_TESTED
    assert report.tests
    assert all(item.status == AssessmentStatus.NOT_TESTED for item in report.tests)
