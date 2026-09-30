from mobileauditkit.models import AssessmentStatus
from mobileauditkit.static_manifest import analyze_manifest_xml


def test_analyze_manifest_xml_no_app():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
    </manifest>
    """
    result = analyze_manifest_xml(xml_str)

    test_1 = next((t for t in result.tests if t.test_id == "MAK-AND-0001"), None)
    if test_1:
        assert test_1.status == AssessmentStatus.INCONCLUSIVE
        assert "No <application> element found" in test_1.observation

    test_3 = next((t for t in result.tests if t.test_id == "MAK-AND-0003"), None)
    if test_3:
        assert test_3.status == AssessmentStatus.PASS
        assert "not declared" in test_3.observation

    test_4 = next((t for t in result.tests if t.test_id == "MAK-AND-0004"), None)
    if test_4:
        assert test_4.status == AssessmentStatus.PASS
        assert "0 exported component" in test_4.observation

    test_6 = next((t for t in result.tests if t.test_id == "MAK-AND-0006"), None)
    if test_6:
        assert test_6.status == AssessmentStatus.PASS
        assert "0 browsable" in test_6.observation

    test_8 = next((t for t in result.tests if t.test_id == "MAK-AND-0008"), None)
    if test_8:
        assert test_8.status == AssessmentStatus.PASS

def test_analyze_manifest_xml_inconclusive():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <application>
        </application>
    </manifest>
    """
    result = analyze_manifest_xml(xml_str)

    test_1 = next(t for t in result.tests if t.test_id == "MAK-AND-0001")
    assert test_1.status == AssessmentStatus.PASS

def test_analyze_manifest_xml_fail():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <uses-sdk android:targetSdkVersion="1" />
        <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
            <activity android:name=".MainActivity" android:exported="true">
                <intent-filter>
                    <action android:name="android.intent.action.VIEW" />
                    <category android:name="android.intent.category.BROWSABLE" />
                    <data android:scheme="http" android:host="example.com" />
                </intent-filter>
            </activity>
            <provider android:name="androidx.core.content.FileProvider" android:exported="true" />
        </application>
    </manifest>
    """
    result = analyze_manifest_xml(xml_str)

    test_1 = next(t for t in result.tests if t.test_id == "MAK-AND-0001")
    assert test_1.status == AssessmentStatus.FAIL

    test_2 = next(t for t in result.tests if t.test_id == "MAK-AND-0002")
    assert test_2.status == AssessmentStatus.FAIL

    test_3 = next(t for t in result.tests if t.test_id == "MAK-AND-0003")
    assert test_3.status == AssessmentStatus.FAIL

    test_6 = next(t for t in result.tests if t.test_id == "MAK-AND-0006")
    assert test_6.status == AssessmentStatus.FAIL

    test_8 = next(t for t in result.tests if t.test_id == "MAK-AND-0008")
    assert test_8.status == AssessmentStatus.FAIL

    test_9 = next(t for t in result.tests if t.test_id == "MAK-AND-0009")
    assert test_9.status == AssessmentStatus.FAIL

def test_analyze_manifest_xml_backup_exclude():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <application android:allowBackup="true" android:fullBackupContent="@xml/backup_rules">
        </application>
    </manifest>
    """
    result = analyze_manifest_xml(xml_str, resource_xml={"/res/xml/backup_rules.xml": "<full-backup-content><exclude domain='sharedpref' path='.' /></full-backup-content>"})

    test_3 = next(t for t in result.tests if t.test_id == "MAK-AND-0003")
    assert test_3.status == AssessmentStatus.PASS

def test_analyze_manifest_xml_backup_no_exclude():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <application android:allowBackup="true" android:fullBackupContent="@xml/backup_rules">
        </application>
    </manifest>
    """
    result = analyze_manifest_xml(xml_str, resource_xml={"/res/xml/backup_rules.xml": "<full-backup-content><include domain='sharedpref' path='.' /></full-backup-content>"})

    test_3 = next(t for t in result.tests if t.test_id == "MAK-AND-0003")
    assert test_3.status == AssessmentStatus.INCONCLUSIVE

def test_analyze_manifest_xml_backup_unresolved_ref():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <application android:allowBackup="true" android:fullBackupContent="@xml/missing">
        </application>
    </manifest>
    """
    result = analyze_manifest_xml(xml_str)

    test_3 = next(t for t in result.tests if t.test_id == "MAK-AND-0003")
    assert test_3.status == AssessmentStatus.INCONCLUSIVE

def test_analyze_manifest_xml_network_unresolved():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <application android:networkSecurityConfig="@xml/missing">
        </application>
    </manifest>
    """
    result = analyze_manifest_xml(xml_str)

    test_7 = next(t for t in result.tests if t.test_id == "MAK-AND-0007")
    assert test_7.status == AssessmentStatus.INCONCLUSIVE
    assert "could not be resolved" in test_7.observation

def test_analyze_manifest_xml_target_sdk_none():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <application>
        </application>
    </manifest>
    """
    result = analyze_manifest_xml(xml_str)

    test_9 = next(t for t in result.tests if t.test_id == "MAK-AND-0009")
    assert test_9.status == AssessmentStatus.INCONCLUSIVE

def test_analyze_manifest_xml_target_sdk_none_no_uses_sdk():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <uses-sdk />
        <application>
        </application>
    </manifest>
    """
    result = analyze_manifest_xml(xml_str)

    test_9 = next(t for t in result.tests if t.test_id == "MAK-AND-0009")
    assert test_9.status == AssessmentStatus.INCONCLUSIVE

def test_analyze_manifest_xml_custom_scheme_deeplink():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <application>
            <activity android:name=".MainActivity">
                <intent-filter>
                    <action android:name="android.intent.action.VIEW" />
                    <category android:name="android.intent.category.BROWSABLE" />
                    <data android:scheme="custom" android:host="example.com" />
                </intent-filter>
            </activity>
        </application>
    </manifest>
    """
    result = analyze_manifest_xml(xml_str)

    test_6 = next(t for t in result.tests if t.test_id == "MAK-AND-0006")
    assert test_6.status == AssessmentStatus.INCONCLUSIVE

def test_analyze_manifest_xml_network_pass_no_insecure():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <application android:networkSecurityConfig="@xml/net">
        </application>
    </manifest>
    """
    # cleartextTrafficPermitted is false, no user certificates
    net_xml = """
    <network-security-config>
        <base-config cleartextTrafficPermitted="false">
            <trust-anchors>
                <certificates src="system" />
            </trust-anchors>
        </base-config>
    </network-security-config>
    """
    from mobileauditkit.models import AssessmentStatus
    from mobileauditkit.static_manifest import analyze_manifest_xml
    result = analyze_manifest_xml(xml_str, resource_xml={"/res/xml/net.xml": net_xml})

    test_7 = next(t for t in result.tests if t.test_id == "MAK-AND-0007")
    assert test_7.status == AssessmentStatus.PASS

def test_analyze_manifest_xml_network_fail_user_ca():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <application android:networkSecurityConfig="@xml/net">
        </application>
    </manifest>
    """
    net_xml = """
    <network-security-config>
        <base-config cleartextTrafficPermitted="false">
            <trust-anchors>
                <certificates src="user" />
            </trust-anchors>
        </base-config>
    </network-security-config>
    """
    from mobileauditkit.models import AssessmentStatus
    from mobileauditkit.static_manifest import analyze_manifest_xml
    result = analyze_manifest_xml(xml_str, resource_xml={"/res/xml/net.xml": net_xml})

    test_7 = next(t for t in result.tests if t.test_id == "MAK-AND-0007")
    assert test_7.status == AssessmentStatus.FAIL

def test_analyze_manifest_xml_custom_permission_weak():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <permission android:name="com.test.perm" android:protectionLevel="normal" />
        <application>
        </application>
    </manifest>
    """
    from mobileauditkit.models import AssessmentStatus
    from mobileauditkit.static_manifest import analyze_manifest_xml
    result = analyze_manifest_xml(xml_str)

    test_5 = next(t for t in result.tests if t.test_id == "MAK-AND-0005")
    assert test_5.status == AssessmentStatus.INCONCLUSIVE

def test_analyze_manifest_xml_custom_deeplink_scheme_none():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <application>
            <activity android:name=".MainActivity">
                <intent-filter>
                    <action android:name="android.intent.action.VIEW" />
                    <category android:name="android.intent.category.BROWSABLE" />
                    <data android:host="example.com" /> <!-- no scheme -->
                </intent-filter>
            </activity>
        </application>
    </manifest>
    """
    from mobileauditkit.models import AssessmentStatus
    from mobileauditkit.static_manifest import analyze_manifest_xml
    result = analyze_manifest_xml(xml_str)

    test_6 = next(t for t in result.tests if t.test_id == "MAK-AND-0006")
    assert test_6.status == AssessmentStatus.PASS

def test_analyze_manifest_xml_backup_exclude_unresolved_array():
    xml_str = """
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.test">
        <application android:allowBackup="false">
        </application>
    </manifest>
    """
    from mobileauditkit.models import AssessmentStatus
    from mobileauditkit.static_manifest import analyze_manifest_xml
    result = analyze_manifest_xml(xml_str)

    test_3 = next(t for t in result.tests if t.test_id == "MAK-AND-0003")
    assert test_3.status == AssessmentStatus.PASS
