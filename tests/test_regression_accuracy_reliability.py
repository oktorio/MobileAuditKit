import json
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from mobileauditkit.apk_config import _scan_packaged_text
from mobileauditkit.assessment import run_assessment
from mobileauditkit.cli import app
from mobileauditkit.event_parser import finding_from_event
from mobileauditkit.models import AssessmentStatus, Severity
from mobileauditkit.profile_loader import AssessmentProfile, ProfileModule
from mobileauditkit.redaction import redact
from mobileauditkit.runner import RuntimeObservation, run_observer
from mobileauditkit.static_manifest import analyze_manifest_xml


def _profile(module: str) -> AssessmentProfile:
    return AssessmentProfile(
        name="regression",
        description="regression",
        modules={module: ProfileModule(fail_threshold=Severity.HIGH)},
    )


def test_agent_error_only_is_inconclusive() -> None:
    observed = RuntimeObservation(
        events=[],
        health={"status": "failed", "errors": ["agent_error"], "dropped_events": 0},
    )
    report = run_assessment(
        package="com.example",
        profile=_profile("network"),
        observer=lambda *args, observed=observed, **kwargs: observed,
    )
    assert report.modules[0].status == AssessmentStatus.INCONCLUSIVE


def test_direct_failure_survives_instrumentation_error() -> None:
    observed = RuntimeObservation(
        events=[{"event": "network_cleartext"}],
        health={"status": "failed", "errors": ["agent_error"], "dropped_events": 0},
    )
    report = run_assessment(
        package="com.example",
        profile=_profile("network"),
        observer=lambda *args, **kwargs: observed,
    )
    assert report.modules[0].status == AssessmentStatus.FAIL


def test_partial_hook_coverage_and_event_limit_are_inconclusive() -> None:
    for status, dropped in [("degraded", 0), ("degraded", 3)]:
        observed = RuntimeObservation(
            events=[{"event": "network_tls_context"}],
            health={"status": status, "errors": [], "dropped_events": dropped},
        )
        report = run_assessment(
            package="com.example",
            profile=_profile("network"),
            observer=lambda *args, **kwargs: observed,
        )
        assert report.modules[0].status == AssessmentStatus.INCONCLUSIVE


def test_target_27_omitted_cleartext_does_not_pass() -> None:
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-sdk android:targetSdkVersion="27"/>
      <application/>
    </manifest>"""
    result = analyze_manifest_xml(manifest)
    status = next(t.status for t in result.tests if t.test_id == "MAK-AND-0002")
    assert status == AssessmentStatus.FAIL


def test_unresolved_target_and_cleartext_is_inconclusive() -> None:
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application/></manifest>"""
    result = analyze_manifest_xml(manifest)
    status = next(t.status for t in result.tests if t.test_id == "MAK-AND-0002")
    assert status == AssessmentStatus.INCONCLUSIVE


def test_network_security_config_inherits_cleartext_from_base() -> None:
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-sdk android:targetSdkVersion="35"/>
      <application android:networkSecurityConfig="@xml/net"/>
    </manifest>"""
    network = """<network-security-config>
      <base-config cleartextTrafficPermitted="true"/>
      <domain-config><domain>example.invalid</domain></domain-config>
    </network-security-config>"""
    result = analyze_manifest_xml(manifest, resource_xml={"/res/xml/net.xml": network})
    status = next(t.status for t in result.tests if t.test_id == "MAK-AND-0007")
    assert status == AssessmentStatus.FAIL


def test_network_security_config_domain_override_cleartext_fails() -> None:
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-sdk android:targetSdkVersion="35"/>
      <application android:networkSecurityConfig="@xml/net"/>
    </manifest>"""
    network = """<network-security-config>
      <base-config cleartextTrafficPermitted="false"/>
      <domain-config cleartextTrafficPermitted="true">
        <domain>example.invalid</domain>
      </domain-config>
    </network-security-config>"""
    result = analyze_manifest_xml(manifest, resource_xml={"/res/xml/net.xml": network})
    status = next(t.status for t in result.tests if t.test_id == "MAK-AND-0007")
    assert status == AssessmentStatus.FAIL


def test_unrelated_backup_exclude_is_not_pass() -> None:
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-sdk android:targetSdkVersion="35"/>
      <application android:allowBackup="true" android:fullBackupContent="@xml/backup"/>
    </manifest>"""
    rules = """<full-backup-content><exclude domain="file" path="cache/tmp.txt"/></full-backup-content>"""
    result = analyze_manifest_xml(manifest, resource_xml={"/res/xml/backup.xml": rules})
    status = next(t.status for t in result.tests if t.test_id == "MAK-AND-0003")
    assert status == AssessmentStatus.INCONCLUSIVE


def test_modern_backup_requires_cloud_and_device_transfer_coverage() -> None:
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-sdk android:targetSdkVersion="35"/>
      <application android:allowBackup="true" android:dataExtractionRules="@xml/data_rules"/>
    </manifest>"""
    domains = "".join(
        f'<exclude domain="{domain}" path="."/>'
        for domain in ("root", "file", "database", "sharedpref", "external")
    )
    cloud_only = f"""<data-extraction-rules>
      <cloud-backup>{domains}</cloud-backup>
      <device-transfer><exclude domain="file" path="."/></device-transfer>
    </data-extraction-rules>"""
    result = analyze_manifest_xml(
        manifest, resource_xml={"/res/xml/data_rules.xml": cloud_only}
    )
    status = next(t.status for t in result.tests if t.test_id == "MAK-AND-0003")
    assert status == AssessmentStatus.INCONCLUSIVE


def test_modern_backup_comprehensive_exclusions_can_pass() -> None:
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-sdk android:targetSdkVersion="35"/>
      <application android:allowBackup="true" android:dataExtractionRules="@xml/data_rules"/>
    </manifest>"""
    domains = "".join(
        f'<exclude domain="{domain}" path="."/>'
        for domain in ("root", "file", "database", "sharedpref", "external")
    )
    rules = f"""<data-extraction-rules>
      <cloud-backup>{domains}</cloud-backup>
      <device-transfer>{domains}</device-transfer>
    </data-extraction-rules>"""
    result = analyze_manifest_xml(
        manifest, resource_xml={"/res/xml/data_rules.xml": rules}
    )
    status = next(t.status for t in result.tests if t.test_id == "MAK-AND-0003")
    assert status == AssessmentStatus.PASS


def test_http_namespace_is_excluded_and_scan_limits_recorded(tmp_path: Path) -> None:
    apk = tmp_path / "x.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("res/layout/a.xml", '<x xmlns:android="http://schemas.android.com/apk/res/android"/>')
    secrets, http, limits = _scan_packaged_text(apk)
    assert secrets == []
    assert http == []
    assert "scanned_bytes" in limits and "truncated" in limits


def test_crypto_rsa_oaep_not_symmetric_ecb() -> None:
    finding = finding_from_event("crypto", {"event": "crypto_algorithm", "algorithm": "RSA/ECB/OAEPPadding"})
    assert finding.severity == Severity.INFO
    assert "Asymmetric" in finding.title


def test_crypto_bare_aes_is_contextual() -> None:
    finding = finding_from_event("crypto", {"event": "crypto_algorithm", "algorithm": "AES"})
    assert finding.severity == Severity.MEDIUM


def test_redaction_normalizes_sensitive_names_and_nested_values() -> None:
    payload = {
        "accessToken": "a",
        "refresh-token": "b",
        "account_number": "c",
        "nested": {"Authorization": "Bearer secretsecretsecret"},
    }
    safe = redact(payload)
    assert safe["accessToken"] == "[REDACTED]"
    assert safe["refresh-token"] == "[REDACTED]"
    assert safe["account_number"] == "[REDACTED]"
    assert safe["nested"]["Authorization"] == "[REDACTED]"


def _install_mock_frida(monkeypatch, *, load_error=False, resume_error=False, interrupt=False):
    device = MagicMock()
    session = MagicMock()
    script = MagicMock()
    device.spawn.return_value = 123
    device.attach.return_value = session
    session.create_script.return_value = script
    if load_error:
        script.load.side_effect = RuntimeError("load failed")
    if resume_error:
        device.resume.side_effect = [RuntimeError("resume failed"), None]
    module = SimpleNamespace(get_usb_device=lambda timeout=5: device)
    monkeypatch.setitem(sys.modules, "frida", module)
    if interrupt:
        monkeypatch.setattr("mobileauditkit.runner.time.sleep", MagicMock(side_effect=KeyboardInterrupt))
    return device, session, script


def test_runner_script_load_failure_cleans_up_and_resumes_spawn(monkeypatch) -> None:
    device, session, script = _install_mock_frida(monkeypatch, load_error=True)
    with pytest.raises(RuntimeError):
        run_observer("com.example", "network", 0.1, spawn=True)
    device.resume.assert_called_with(123)
    session.detach.assert_called_once()


def test_runner_resume_failure_attempts_recovery_and_detaches(monkeypatch) -> None:
    device, session, script = _install_mock_frida(monkeypatch, resume_error=True)
    with pytest.raises(RuntimeError):
        run_observer("com.example", "network", 0.1, spawn=True)
    assert device.resume.call_count == 2
    session.detach.assert_called_once()


def test_runner_cancellation_returns_incomplete_and_detaches(monkeypatch) -> None:
    device, session, script = _install_mock_frida(monkeypatch, interrupt=True)
    result = run_observer("com.example", "network", 0.1, spawn=False)
    assert result.interrupted is True
    assert result.health["status"] == "incomplete"
    session.detach.assert_called_once()


def test_static_profile_without_apk_is_cli_input_error() -> None:
    result = CliRunner().invoke(app, ["scan", "--profile", "static"])
    assert result.exit_code != 0
    assert "requires --apk" in result.output


def test_exit_policy_preserves_report(tmp_path: Path, monkeypatch) -> None:
    report_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    monkeypatch.setattr(
        "mobileauditkit.cli.run_assessment",
        lambda **kwargs: SimpleNamespace(
            assessment_id="x", profile="runtime",
            modules=[SimpleNamespace(module="network", status="INCONCLUSIVE", event_count=0, finding_count=0, test_ids=[], highest_severity=None)],
            coverage=SimpleNamespace(execution_coverage_percent=100.0, conclusive_coverage_percent=0.0),
            tests=[], evidence=[], masvs_coverage=[],
        ),
    )
    monkeypatch.setattr("mobileauditkit.cli.write_assessment_json", lambda report, path: path.write_text(json.dumps({"ok": True})) or path)
    monkeypatch.setattr("mobileauditkit.cli.write_assessment_html", lambda report, path: path.write_text("ok") or path)
    result = CliRunner().invoke(app, [
        "scan", "--profile", "runtime", "--package", "com.example",
        "--json-report", str(report_path), "--html-report", str(html_path), "--exit-on-incomplete",
    ])
    assert result.exit_code == 3
    assert report_path.exists() and html_path.exists()
