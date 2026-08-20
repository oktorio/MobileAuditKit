from pathlib import Path

from mobileauditkit.assessment import run_assessment
from mobileauditkit.models import (
    DynamicSessionResult,
    FlowMarker,
    HookHealth,
    HookHealthState,
    RuntimeFingerprint,
    Severity,
)
from mobileauditkit.profile_loader import AssessmentProfile, ProfileModule
from mobileauditkit.reporting import (
    assessment_to_sarif,
    write_assessment_html,
    write_assessment_json,
)


def _report():
    profile = AssessmentProfile(
        name="runtime-report",
        description="fixture",
        modules={"network": ProfileModule(fail_threshold=Severity.HIGH)},
    )

    def session_runner(package, modules, seconds, *, spawn=False, flow="default"):
        health = HookHealth(
            module="network",
            state=HookHealthState.READY,
            script_loaded=True,
            signal_received=True,
            hooks_attempted=5,
            hooks_installed=5,
            security_event_count=1,
        )
        return DynamicSessionResult(
            package=package,
            modules=modules,
            events={"network": [{"event": "network_cleartext", "flow": flow}]},
            hook_health={"network": health},
            fingerprint=RuntimeFingerprint(
                fingerprint_id="FP-REPORT",
                package=package,
                app_version_name="5.0",
                app_version_code="500",
                android_version="16",
                api_level=36,
                model="LabDevice",
                frida_version="17.17.0",
                device_id_hash="ABCDEF0123456789",
            ),
            flows=[
                FlowMarker(marker_id="FLOW-A", flow=flow, phase="start"),
                FlowMarker(marker_id="FLOW-B", flow=flow, phase="end"),
            ],
            duration_seconds=2.0,
        )

    return run_assessment(
        package="com.example",
        profile=profile,
        flow="login",
        session_runner=session_runner,
    )


def test_json_and_html_include_flow_fingerprint_and_hook_health(tmp_path: Path) -> None:
    report = _report()
    json_path = write_assessment_json(report, tmp_path / "assessment.json")
    html_path = write_assessment_html(report, tmp_path / "assessment.html")
    json_text = json_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")
    assert "FP-REPORT" in json_text
    assert "ABCDEF0123456789" in json_text
    assert '"flow": "login"' in json_text
    assert '"state": "READY"' in json_text
    assert "Runtime fingerprint" in html_text
    assert "Hook health" in html_text
    assert "FLOW-A" in html_text


def test_sarif_carries_flow_and_runtime_fingerprint_id() -> None:
    report = _report()
    sarif = assessment_to_sarif(report)
    props = sarif["runs"][0]["properties"]
    assert props["flow"] == "login"
    assert props["runtime_fingerprint_id"] == "FP-REPORT"
