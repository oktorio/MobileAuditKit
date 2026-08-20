from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

from mobileauditkit.evidence import make_evidence, sha256_file
from mobileauditkit.models import AssessmentStatus, Finding, Severity, StaticAnalysisResult
from mobileauditkit.static_manifest import analyze_manifest_xml
from mobileauditkit.static_support import A, _append, _finding, _resource_path
from mobileauditkit.test_registry import get_test

_TEXT_SUFFIXES = {".json", ".xml", ".txt", ".html", ".htm", ".js", ".properties", ".conf", ".ini", ".yaml", ".yml"}
_SECRET_PATTERNS = {
    "private_key_marker": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    "jwt_like": re.compile(rb"eyJ[0-9A-Za-z_-]{8,}\\.[0-9A-Za-z_-]{8,}\\.[0-9A-Za-z_-]{4,}"),
}
_HTTP = re.compile(rb"http://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+", re.I)


def parse_manifest_xml(xml_text: str) -> list[Finding]:
    """Backward-compatible manifest findings-only interface."""
    return analyze_manifest_xml(xml_text).findings


def _run(tool: str, args: list[str], *, timeout: int = 30) -> str:
    result = subprocess.run([tool, *args], check=True, capture_output=True, text=True, timeout=timeout)
    return result.stdout


def _scan_packaged_text(apk_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    secret_hits: list[dict[str, Any]] = []
    http_hits: list[dict[str, Any]] = []
    total = 0
    with zipfile.ZipFile(apk_path) as archive:
        for info in archive.infolist():
            path = Path(info.filename)
            if info.is_dir() or path.suffix.lower() not in _TEXT_SUFFIXES or info.file_size > 512 * 1024:
                continue
            if total + info.file_size > 5 * 1024 * 1024:
                break
            total += info.file_size
            try:
                data = archive.read(info)[: 512 * 1024]
            except (KeyError, RuntimeError):
                continue
            for indicator, pattern in _SECRET_PATTERNS.items():
                count = len(pattern.findall(data))
                if count:
                    secret_hits.append({"file": info.filename, "indicator": indicator, "count": count})
            count = len(_HTTP.findall(data))
            if count:
                http_hits.append({"file": info.filename, "indicator": "cleartext_http", "count": count})
    return secret_hits, http_hits


def _append_package_content(output: StaticAnalysisResult, apk_path: Path) -> None:
    secrets, http = _scan_packaged_text(apk_path)
    test = get_test("MAK-AND-0011")
    finding = _finding(test, "MAK-APK-SECRET-INDICATORS", "High-confidence packaged secret indicators observed", "Bounded packaged-text scanning found one or more high-confidence secret formats. Matched values are intentionally not persisted.", Severity.HIGH, output.metadata.get("package"), {}, remediation="Remove embedded secrets; use server-side or platform-backed secret management as appropriate.") if secrets else None
    _append(output, test, AssessmentStatus.FAIL if secrets else AssessmentStatus.PASS, f"High-confidence secret indicator occurrences={sum(x['count'] for x in secrets)}.", "Only indicator type, file path, and count are retained; matched values are discarded.", evidence_data={"indicators": secrets}, evidence_type="bounded-package-text-scan", source=apk_path.name, finding=finding)

    test = get_test("MAK-AND-0012")
    finding = _finding(test, "MAK-APK-HTTP-INDICATORS", "Packaged cleartext HTTP endpoint indicators observed", "Bounded packaged-text scanning found cleartext HTTP scheme indicators. Endpoint values are intentionally not persisted.", Severity.MEDIUM, output.metadata.get("package"), {}, remediation="Review each cleartext endpoint indicator and migrate production communication to HTTPS/TLS.") if http else None
    _append(output, test, AssessmentStatus.FAIL if http else AssessmentStatus.PASS, f"Cleartext HTTP indicator occurrences={sum(x['count'] for x in http)}.", "Only file path and count are retained; endpoint values and query data are discarded.", evidence_data={"indicators": http}, evidence_type="bounded-package-text-scan", source=apk_path.name, finding=finding)


def _append_native_inventory(output: StaticAnalysisResult, apk_path: Path) -> None:
    libraries: list[dict[str, str]] = []
    with zipfile.ZipFile(apk_path) as archive:
        for name in archive.namelist():
            parts = name.split("/")
            if len(parts) == 3 and parts[0] == "lib" and name.endswith(".so"):
                libraries.append({"abi": parts[1], "library": parts[2]})
    test = get_test("MAK-AND-0014")
    _append(output, test, AssessmentStatus.PASS, f"Collected {len(libraries)} native library declaration(s) across {len({x['abi'] for x in libraries})} ABI(s).", "PASS indicates inventory completion only; native-code security requires separate review.", evidence_data={"libraries": libraries, "library_count": len(libraries)}, evidence_type="native-library-inventory", source=apk_path.name)


def _append_signing(output: StaticAnalysisResult, apk_path: Path) -> None:
    test = get_test("MAK-AND-0013")
    tool = shutil.which("apksigner")
    if not tool:
        _append(output, test, AssessmentStatus.NOT_TESTED, "apksigner is not available on PATH.", "Signing metadata collection is optional and does not affect other static checks.", evidence_data={"apksigner_available": False}, evidence_type="signing-metadata", source=apk_path.name)
        return
    try:
        text = _run(tool, ["verify", "--print-certs", str(apk_path)])
        fingerprints = re.findall(r"certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", text)
        status = AssessmentStatus.PASS if fingerprints else AssessmentStatus.INCONCLUSIVE
        _append(output, test, status, f"Collected {len(fingerprints)} signing certificate SHA-256 fingerprint(s).", "Collection success does not validate publisher identity or signing policy.", evidence_data={"signer_count": len(fingerprints), "certificate_sha256": fingerprints}, evidence_type="signing-metadata", source=apk_path.name)
    except (subprocess.SubprocessError, OSError):
        _append(output, test, AssessmentStatus.INCONCLUSIVE, "Signing metadata collection failed.", "The optional signing metadata step was not reliable.", evidence_data={"collection_succeeded": False}, evidence_type="signing-metadata", source=apk_path.name)


def _append_package_inventory(output: StaticAnalysisResult, apk_path: Path, apkanalyzer: str) -> None:
    test = get_test("MAK-AND-0015")
    app_package = str(output.metadata.get("package") or "")
    try:
        text = _run(apkanalyzer, ["dex", "packages", "--defined-only", str(apk_path)], timeout=45)
        packages: set[str] = set()
        for line in text.splitlines():
            if not line.startswith("P "):
                continue
            name = line.split()[-1]
            if app_package and (name == app_package or name.startswith(f"{app_package}.")):
                continue
            if name.startswith(("android.", "java.", "javax.", "kotlin.", "kotlinx.")):
                continue
            packages.add(name)
        inventory = sorted(packages)[:200]
        _append(output, test, AssessmentStatus.PASS, f"Collected {len(inventory)} non-application package namespace(s), capped at 200.", "Namespace inventory supports supply-chain review but does not infer versions or vulnerabilities.", evidence_data={"package_namespaces": inventory, "truncated": len(packages) > 200}, evidence_type="dex-package-inventory", source=apk_path.name)
    except (subprocess.SubprocessError, OSError):
        _append(output, test, AssessmentStatus.NOT_TESTED, "DEX package inventory could not be collected.", "This inventory step is optional and independent from manifest checks.", evidence_data={"collection_succeeded": False}, evidence_type="dex-package-inventory", source=apk_path.name)


def inspect_apk_detailed(apk_path: Path) -> StaticAnalysisResult:
    if not apk_path.is_file():
        raise FileNotFoundError(apk_path)
    apkanalyzer = shutil.which("apkanalyzer")
    if not apkanalyzer:
        raise RuntimeError("apkanalyzer not found. Install Android SDK tooling and add it to PATH.")
    manifest = _run(apkanalyzer, ["manifest", "print", str(apk_path)])
    root = ET.fromstring(manifest)
    app = root.find("application")
    resources: dict[str, str] = {}
    if app is not None:
        for reference in {app.attrib.get(f"{A}networkSecurityConfig"), app.attrib.get(f"{A}fullBackupContent"), app.attrib.get(f"{A}dataExtractionRules")}:
            path = _resource_path(reference)
            if not path:
                continue
            try:
                resources[path] = _run(apkanalyzer, ["resources", "xml", "--file", path, str(apk_path)])
            except subprocess.SubprocessError:
                pass
    output = analyze_manifest_xml(manifest, resource_xml=resources)
    digest = sha256_file(apk_path)
    output.metadata.update({"apk": apk_path.name, "apk_sha256": digest, "apk_size_bytes": apk_path.stat().st_size, "static_engine": "apkanalyzer+zipfile"})
    output.evidence.append(make_evidence(source=apk_path.name, module="apk-config", test_id=None, evidence_type="artifact-identity", data={"apk": apk_path.name, "sha256": digest, "size_bytes": apk_path.stat().st_size}))
    _append_package_content(output, apk_path)
    _append_native_inventory(output, apk_path)
    _append_signing(output, apk_path)
    _append_package_inventory(output, apk_path, apkanalyzer)
    return output


def inspect_apk(apk_path: Path) -> list[Finding]:
    """Backward-compatible findings-only interface."""
    return inspect_apk_detailed(apk_path).findings
