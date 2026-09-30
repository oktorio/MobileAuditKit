from mobileauditkit.event_parser import finding_from_event
from mobileauditkit.models import Severity, Confidence

def test_crypto_algorithm():
    event = {"event": "crypto_algorithm", "algorithm": "MD5"}
    finding = finding_from_event("crypto", event)
    assert finding.severity == Severity.HIGH

    event = {"event": "crypto_algorithm", "algorithm": "AES/ECB/PKCS5Padding"}
    finding = finding_from_event("crypto", event)
    assert finding.severity == Severity.HIGH

    event = {"event": "crypto_algorithm", "algorithm": "AES/CBC/PKCS5Padding"}
    finding = finding_from_event("crypto", event)
    assert finding.severity == Severity.INFO

def test_storage():
    event = {"event": "storage_external"}
    finding = finding_from_event("storage", event)
    assert finding.severity == Severity.MEDIUM

    event = {"event": "storage_shared_preferences"}
    finding = finding_from_event("storage", event)
    assert finding.severity == Severity.INFO

def test_network():
    event = {"event": "network_pinning"}
    finding = finding_from_event("network", event)
    assert finding.severity == Severity.INFO

    event = {"event": "network_tls_context"}
    finding = finding_from_event("network", event)
    assert finding.severity == Severity.INFO

def test_biometric():
    event = {"event": "biometric_authentication", "crypto_bound": True}
    finding = finding_from_event("authentication", event)
    assert finding.severity == Severity.INFO

def test_webview():
    event = {"event": "webview_snapshot", "allowFileAccess": True}
    finding = finding_from_event("webview", event)
    assert finding.severity == Severity.MEDIUM

    event = {"event": "webview_snapshot", "allowFileAccess": False}
    finding = finding_from_event("webview", event)
    assert finding.severity == Severity.INFO

    event = {"event": "webview_debugging", "enabled": True}
    finding = finding_from_event("webview", event)
    assert finding.severity == Severity.MEDIUM

    event = {"event": "webview_debugging", "enabled": False}
    finding = finding_from_event("webview", event)
    assert finding.severity == Severity.INFO

    event = {"event": "webview_javascript_interface"}
    finding = finding_from_event("webview", event)
    assert finding.severity == Severity.MEDIUM

def test_privacy():
    event = {"event": "privacy_clipboard_write"}
    finding = finding_from_event("privacy", event)
    assert finding.severity == Severity.LOW

    event = {"event": "privacy_log_call"}
    finding = finding_from_event("privacy", event)
    assert finding.severity == Severity.INFO

def test_resilience():
    event = {"event": "resilience_root_check"}
    finding = finding_from_event("resilience", event)
    assert finding.severity == Severity.INFO

def test_agent_error():
    event = {"event": "agent_error"}
    finding = finding_from_event("crypto", event)
    assert finding.severity == Severity.INFO

def test_unknown_event():
    event = {"event": "unknown_event"}
    finding = finding_from_event("crypto", event)
    assert finding.severity == Severity.INFO
