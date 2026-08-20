from mobileauditkit.apk_config import parse_manifest_xml
from mobileauditkit.models import Severity

MANIFEST = r'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.audit">
<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
<application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
  <activity android:name=".ExportedActivity" android:exported="true" />
</application>
</manifest>'''


def test_manifest_checks() -> None:
    findings = parse_manifest_xml(MANIFEST)
    titles = {finding.title for finding in findings}
    assert "Application is explicitly debuggable" in titles
    assert "Application backup is enabled" in titles
    assert "Manifest explicitly permits cleartext traffic" in titles
    assert any("Exported activity" in title for title in titles)
    assert any(finding.severity == Severity.HIGH for finding in findings)
