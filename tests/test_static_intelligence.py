import zipfile
from pathlib import Path

from mobileauditkit.apk_config import analyze_manifest_xml, inspect_apk_detailed
from mobileauditkit.models import AssessmentStatus

MANIFEST = r'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.audit" android:versionCode="4" android:versionName="1.2">
<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
<uses-permission android:name="android.permission.CAMERA" />
<permission android:name="com.example.audit.INTERNAL" android:protectionLevel="signature" />
<application android:debuggable="false" android:allowBackup="false" android:usesCleartextTraffic="false" android:networkSecurityConfig="@xml/network_security_config">
  <activity android:name=".MainActivity" android:exported="true">
    <intent-filter>
      <action android:name="android.intent.action.MAIN" />
      <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
  </activity>
  <provider android:name="androidx.core.content.FileProvider" android:authorities="com.example.files" android:exported="false" android:grantUriPermissions="true" />
</application>
</manifest>'''

NETWORK = r'''<network-security-config><base-config cleartextTrafficPermitted="false"><trust-anchors><certificates src="system" /></trust-anchors></base-config></network-security-config>'''


def _statuses(result):
    return {item.test_id: item.status for item in result.tests}


def test_manifest_atomic_checks_are_conservative() -> None:
    result = analyze_manifest_xml(MANIFEST, resource_xml={"/res/xml/network_security_config.xml": NETWORK})
    statuses = _statuses(result)
    assert statuses["MAK-AND-0001"] == AssessmentStatus.PASS
    assert statuses["MAK-AND-0007"] == AssessmentStatus.PASS
    assert statuses["MAK-AND-0008"] == AssessmentStatus.PASS
    assert statuses["MAK-AND-0009"] == AssessmentStatus.PASS
    assert statuses["MAK-AND-0010"] == AssessmentStatus.PASS


def test_network_security_config_weakening_fails() -> None:
    weak = r'''<network-security-config><base-config cleartextTrafficPermitted="true"><trust-anchors><certificates src="user" /></trust-anchors></base-config></network-security-config>'''
    result = analyze_manifest_xml(MANIFEST, resource_xml={"/res/xml/network_security_config.xml": weak})
    test = next(item for item in result.tests if item.test_id == "MAK-AND-0007")
    assert test.status == AssessmentStatus.FAIL
    assert any(finding.test_id == "MAK-AND-0007" for finding in result.findings)


def test_exported_non_entry_component_is_inconclusive_not_confirmed() -> None:
    manifest = MANIFEST.replace("</application>", '<service android:name=".SyncService" android:exported="true" /></application>')
    result = analyze_manifest_xml(manifest, resource_xml={"/res/xml/network_security_config.xml": NETWORK})
    test = next(item for item in result.tests if item.test_id == "MAK-AND-0004")
    assert test.status == AssessmentStatus.INCONCLUSIVE
    indicators = [finding for finding in result.findings if finding.test_id == "MAK-AND-0004"]
    assert indicators
    assert all(finding.confidence == "Observed" for finding in indicators)


def test_detailed_apk_scan_discards_secret_values(monkeypatch, tmp_path: Path) -> None:
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/config.json", '{"api_key":"AIza' + "A" * 35 + '","url":"http://example.invalid"}')
        archive.writestr("lib/arm64-v8a/libsample.so", b"not-a-real-library")

    def fake_which(name: str):
        return "/tools/apkanalyzer" if name == "apkanalyzer" else None

    def fake_run(tool: str, args: list[str], *, timeout: int = 30):
        if args[:2] == ["manifest", "print"]:
            return MANIFEST
        if args[:2] == ["resources", "xml"]:
            return NETWORK
        if args[:3] == ["dex", "packages", "--defined-only"]:
            return "P d 1 1 10 com.example.audit\nP d 1 1 10 com.vendor.sdk\n"
        raise AssertionError(args)

    monkeypatch.setattr("mobileauditkit.apk_config.shutil.which", fake_which)
    monkeypatch.setattr("mobileauditkit.apk_config._run", fake_run)
    result = inspect_apk_detailed(apk)
    payload = result.model_dump_json()
    assert "AIza" not in payload
    assert "http://example.invalid" not in payload
    assert result.metadata["apk_sha256"]
    assert any(item.test_id == "MAK-AND-0011" and item.status == AssessmentStatus.FAIL for item in result.tests)
    assert any(item.test_id == "MAK-AND-0012" and item.status == AssessmentStatus.FAIL for item in result.tests)
    assert any(item.test_id == "MAK-AND-0014" for item in result.tests)
