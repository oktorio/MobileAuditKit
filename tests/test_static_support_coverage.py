from mobileauditkit.static_support import _bool, _int, _resource_path, _has_launcher_or_browsable
import xml.etree.ElementTree as ET

def test_bool():
    assert _bool(None) is None
    assert _bool("true") is True
    assert _bool("TRUE") is True
    assert _bool("false") is False
    assert _bool("FALSE") is False
    assert _bool("invalid") is None

def test_int():
    assert _int(None) is None
    assert _int("123") == 123
    assert _int("invalid") is None

def test_resource_path():
    assert _resource_path(None) is None
    assert _resource_path("invalid") is None
    assert _resource_path("@xml/network_security_config") == "/res/xml/network_security_config.xml"

def test_has_launcher_or_browsable():
    # launcher
    xml = """
    <activity xmlns:android="http://schemas.android.com/apk/res/android">
        <intent-filter>
            <action android:name="android.intent.action.MAIN" />
            <category android:name="android.intent.category.LAUNCHER" />
        </intent-filter>
    </activity>
    """
    root = ET.fromstring(xml)
    assert _has_launcher_or_browsable(root) is True

    # browsable
    xml = """
    <activity xmlns:android="http://schemas.android.com/apk/res/android">
        <intent-filter>
            <action android:name="android.intent.action.VIEW" />
            <category android:name="android.intent.category.BROWSABLE" />
        </intent-filter>
    </activity>
    """
    root = ET.fromstring(xml)
    assert _has_launcher_or_browsable(root) is True

    # neither
    xml = """
    <activity xmlns:android="http://schemas.android.com/apk/res/android">
        <intent-filter>
            <action android:name="android.intent.action.VIEW" />
            <category android:name="android.intent.category.DEFAULT" />
        </intent-filter>
    </activity>
    """
    root = ET.fromstring(xml)
    assert _has_launcher_or_browsable(root) is False
