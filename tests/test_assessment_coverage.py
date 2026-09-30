
import pytest

from mobileauditkit.assessment import _dynamic_test_definition, run_assessment


def test_run_assessment_dynamic_exception(monkeypatch):
    def mock_observer(*args, **kwargs):
        raise RuntimeError("test exception")

    result = run_assessment(package="com.example", profile="runtime", seconds=0.1, observer=mock_observer)

    # Verify exception is handled and module is in INCONCLUSIVE status
    assert len(result.modules) > 0
    crypto_module = next((m for m in result.modules if m.module == "crypto"), None)
    if crypto_module:
        assert crypto_module.status == "INCONCLUSIVE"
        assert "RuntimeError: test exception" in crypto_module.error

def test_run_assessment_static_exception(monkeypatch, tmp_path):
    def mock_apk_inspector(*args, **kwargs):
        raise RuntimeError("test static exception")

    apk = tmp_path / "test.apk"
    apk.write_text("dummy")

    result = run_assessment(package="com.example", apk_path=apk, profile="static", apk_inspector=mock_apk_inspector)

    assert len(result.modules) > 0
    apk_module = next((m for m in result.modules if m.module == "apk-config"), None)
    if apk_module:
        assert apk_module.status == "INCONCLUSIVE"
        assert "RuntimeError: test static exception" in apk_module.error

def test_missing_dynamic_test_definition(monkeypatch):
    import mobileauditkit.assessment
    monkeypatch.setattr(mobileauditkit.assessment, "tests_for_module", lambda *args, **kwargs: [])
    result = _dynamic_test_definition("crypto")
    assert result is None

def test_static_module_without_apk():
    result = run_assessment(package="com.example", profile="static", seconds=0.1)
    apk_module = next((m for m in result.modules if m.module == "apk-config"), None)
    assert apk_module
    assert apk_module.status == "NOT_TESTED"
    assert "APK was supplied" in apk_module.observation

def test_run_assessment_invalid_seconds():
    with pytest.raises(ValueError, match="seconds must be greater than zero"):
        run_assessment(package="com.example", seconds=0)

    with pytest.raises(ValueError, match="seconds must be greater than zero"):
        run_assessment(package="com.example", seconds=4000)
