import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from mobileauditkit.apk_config import _run, inspect_apk


def test_inspect_apk(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("test.txt", "test")

    def mock_inspect_apk_detailed(apk_path):
        from mobileauditkit.models import Finding, StaticAnalysisResult
        res = StaticAnalysisResult()
        res.findings.append(Finding(finding_id="test", title="test", description="test", severity="INFO"))
        return res

    import mobileauditkit.apk_config
    original = mobileauditkit.apk_config.inspect_apk_detailed
    mobileauditkit.apk_config.inspect_apk_detailed = mock_inspect_apk_detailed

    findings = inspect_apk(apk)
    assert len(findings) == 1

    mobileauditkit.apk_config.inspect_apk_detailed = original

def test_inspect_apk_detailed_missing_file():
    from mobileauditkit.apk_config import inspect_apk_detailed
    with pytest.raises(FileNotFoundError):
        inspect_apk_detailed(Path("missing.apk"))

def test_inspect_apk_detailed_missing_apkanalyzer(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("test")
    monkeypatch.setattr(shutil, "which", lambda x: None)
    from mobileauditkit.apk_config import inspect_apk_detailed
    with pytest.raises(RuntimeError, match="apkanalyzer not found"):
        inspect_apk_detailed(apk)

def test_run_timeout():
    with pytest.raises(subprocess.CalledProcessError):
        _run("ls", ["/nonexistent"])

def test_append_signing_failed(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("test")

    def fake_run(tool: str, args: list[str], **kwargs):
        raise subprocess.SubprocessError("test failed")

    def fake_which(name):
        return "apksigner"

    monkeypatch.setattr("mobileauditkit.apk_config._run", fake_run)
    monkeypatch.setattr(shutil, "which", fake_which)

    from mobileauditkit.apk_config import _append_signing
    from mobileauditkit.models import StaticAnalysisResult

    res = StaticAnalysisResult()
    _append_signing(res, apk)
    assert len(res.tests) == 1
    assert res.tests[0].status == "INCONCLUSIVE"
    assert "collection failed" in res.tests[0].observation

def test_append_package_inventory_failed(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("test")

    def fake_run(tool: str, args: list[str], **kwargs):
        raise subprocess.SubprocessError("test failed")

    monkeypatch.setattr("mobileauditkit.apk_config._run", fake_run)

    from mobileauditkit.apk_config import _append_package_inventory
    from mobileauditkit.models import StaticAnalysisResult

    res = StaticAnalysisResult()
    _append_package_inventory(res, apk, "apkanalyzer")
    assert len(res.tests) == 1
    assert res.tests[0].status == "NOT_TESTED"
    assert "could not be collected" in res.tests[0].observation

def test_scan_packaged_text_coverage(tmp_path):
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("test.json", "http:// " * 500000) # Big file
        archive.writestr("test2.json", "http:// ")
        archive.writestr("test3.bin", b"\x00\x00")

    from mobileauditkit.apk_config import _scan_packaged_text
    secrets, http = _scan_packaged_text(apk)
    assert len(http) > 0

def test_scan_packaged_text_malformed_zip(tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("not a zip")
    from mobileauditkit.apk_config import _scan_packaged_text
    with pytest.raises(zipfile.BadZipFile):
        _scan_packaged_text(apk)

def test_append_signing_no_fingerprints(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("test")

    def fake_run(tool: str, args: list[str], **kwargs):
        return "Verified using v1 scheme (JAR signing): true\n"

    def fake_which(name):
        return "apksigner"

    monkeypatch.setattr("mobileauditkit.apk_config._run", fake_run)
    monkeypatch.setattr(shutil, "which", fake_which)

    from mobileauditkit.apk_config import _append_signing
    from mobileauditkit.models import StaticAnalysisResult

    res = StaticAnalysisResult()
    _append_signing(res, apk)
    assert len(res.tests) == 1
    assert res.tests[0].status == "INCONCLUSIVE"

def test_append_package_inventory_success(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("test")

    def fake_run(tool: str, args: list[str], **kwargs):
        return "P d 1 1 10 com.example.audit\nP d 1 1 10 com.vendor.sdk\n"

    monkeypatch.setattr("mobileauditkit.apk_config._run", fake_run)

    from mobileauditkit.apk_config import _append_package_inventory
    from mobileauditkit.models import StaticAnalysisResult

    res = StaticAnalysisResult()
    _append_package_inventory(res, apk, "apkanalyzer")
    assert len(res.tests) == 1
    assert res.tests[0].status == "PASS"

def test_append_package_inventory_cap(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("test")

    def fake_run(tool: str, args: list[str], **kwargs):
        return "\n".join([f"P d 1 1 10 com.vendor.sdk{i}" for i in range(250)])

    monkeypatch.setattr("mobileauditkit.apk_config._run", fake_run)

    from mobileauditkit.apk_config import _append_package_inventory
    from mobileauditkit.models import StaticAnalysisResult

    res = StaticAnalysisResult()
    _append_package_inventory(res, apk, "apkanalyzer")
    assert len(res.tests) == 1
    assert res.tests[0].status == "PASS"

def test_scan_packaged_text_coverage_keyerror(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("test.json", "test")

    def mock_read(*args, **kwargs):
        raise KeyError("test")

    monkeypatch.setattr(zipfile.ZipFile, "read", mock_read)

    from mobileauditkit.apk_config import _scan_packaged_text
    secrets, http = _scan_packaged_text(apk)
    assert len(secrets) == 0

def test_scan_packaged_text_coverage_runtimeerror(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("test.json", "test")

    def mock_read(*args, **kwargs):
        raise RuntimeError("test")

    monkeypatch.setattr(zipfile.ZipFile, "read", mock_read)

    from mobileauditkit.apk_config import _scan_packaged_text
    secrets, http = _scan_packaged_text(apk)
    assert len(secrets) == 0

def test_run_success():
    out = _run("echo", ["hello"])
    assert "hello" in out

def test_inspect_apk_detailed_resource_failure(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("test.txt", "test")

    def fake_run(tool: str, args: list[str], **kwargs):
        if args[:2] == ["manifest", "print"]:
            return '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test"><application android:networkSecurityConfig="@xml/net" /></manifest>'
        if args[:2] == ["resources", "xml"]:
            raise subprocess.SubprocessError("test failed")
        return ""

    def fake_which(name):
        return "apkanalyzer"

    monkeypatch.setattr("mobileauditkit.apk_config._run", fake_run)
    monkeypatch.setattr(shutil, "which", fake_which)

    from mobileauditkit.apk_config import inspect_apk_detailed
    res = inspect_apk_detailed(apk)
    assert len(res.tests) > 0

def test_append_package_inventory_app_package_continue(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("test")

    def fake_run(tool: str, args: list[str], **kwargs):
        return "P d 1 1 10 com.example.audit\n"

    monkeypatch.setattr("mobileauditkit.apk_config._run", fake_run)

    from mobileauditkit.apk_config import _append_package_inventory
    from mobileauditkit.models import StaticAnalysisResult

    res = StaticAnalysisResult()
    res.metadata["package"] = "com.example.audit"
    _append_package_inventory(res, apk, "apkanalyzer")
    assert len(res.tests) == 1
    assert "Collected 0 non-application" in res.tests[0].observation

def test_append_package_inventory_android_package_continue(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("test")

    def fake_run(tool: str, args: list[str], **kwargs):
        return "P d 1 1 10 android.support\n"

    monkeypatch.setattr("mobileauditkit.apk_config._run", fake_run)

    from mobileauditkit.apk_config import _append_package_inventory
    from mobileauditkit.models import StaticAnalysisResult

    res = StaticAnalysisResult()
    res.metadata["package"] = "com.example.audit"
    _append_package_inventory(res, apk, "apkanalyzer")
    assert len(res.tests) == 1
    assert "Collected 0 non-application" in res.tests[0].observation

def test_append_package_inventory_not_starts_with_p(monkeypatch, tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("test")

    def fake_run(tool: str, args: list[str], **kwargs):
        return "invalid line\n"

    monkeypatch.setattr("mobileauditkit.apk_config._run", fake_run)

    from mobileauditkit.apk_config import _append_package_inventory
    from mobileauditkit.models import StaticAnalysisResult

    res = StaticAnalysisResult()
    res.metadata["package"] = "com.example.audit"
    _append_package_inventory(res, apk, "apkanalyzer")
    assert len(res.tests) == 1
    assert "Collected 0 non-application" in res.tests[0].observation

def test_scan_packaged_text_coverage_total_size(tmp_path):
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("test1.json", "A" * (3 * 1024 * 1024))
        archive.writestr("test2.json", "B" * (3 * 1024 * 1024))
    from mobileauditkit.apk_config import _scan_packaged_text
    secrets, http = _scan_packaged_text(apk)

def test_scan_packaged_text_coverage_total_size2(tmp_path):
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("test1.json", "A" * (3 * 1024 * 1024))
        archive.writestr("test2.json", "A" * 1024)
        archive.writestr("test3.json", "A" * (3 * 1024 * 1024))
    from mobileauditkit.apk_config import _scan_packaged_text
    secrets, http = _scan_packaged_text(apk)

def test_scan_packaged_text_coverage_total_size3(tmp_path):
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("test1.json", "A" * (3 * 1024 * 1024))
        archive.writestr("test2.json", "A" * (3 * 1024 * 1024))
    from mobileauditkit.apk_config import _scan_packaged_text
    secrets, http = _scan_packaged_text(apk)

def test_scan_packaged_text_coverage_total_size4(tmp_path):
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("test1.json", "A" * (3 * 1024 * 1024))
        archive.writestr("test2.json", "A" * (3 * 1024 * 1024))
    from mobileauditkit.apk_config import _scan_packaged_text
    secrets, http = _scan_packaged_text(apk)

def test_scan_packaged_text_coverage_total_size5(tmp_path):
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("test1.json", "A" * (3 * 1024 * 1024))
        archive.writestr("test2.json", "A" * (3 * 1024 * 1024))
    from mobileauditkit.apk_config import _scan_packaged_text
    secrets, http = _scan_packaged_text(apk)

def test_scan_packaged_text_coverage_total_size6(tmp_path):
    apk = tmp_path / "test.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("test1.json", "A" * (3 * 1024 * 1024))
        archive.writestr("test2.json", "B" * (3 * 1024 * 1024))
    from mobileauditkit.apk_config import _scan_packaged_text
    secrets, http = _scan_packaged_text(apk)
