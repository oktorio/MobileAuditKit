from __future__ import annotations

import hashlib
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from mobileauditkit.models import Confidence, Finding, Severity

ANDROID_NS = "http://schemas.android.com/apk/res/android"
A = f"{{{ANDROID_NS}}}"


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return None


def parse_manifest_xml(xml_text: str) -> list[Finding]:
    root = ET.fromstring(xml_text)
    package = root.attrib.get("package")
    app = root.find("application")
    if app is None:
        return []
    findings: list[Finding] = []
    debuggable = _bool(app.attrib.get(f"{A}debuggable"))
    allow_backup = _bool(app.attrib.get(f"{A}allowBackup"))
    cleartext = _bool(app.attrib.get(f"{A}usesCleartextTraffic"))
    network_config = app.attrib.get(f"{A}networkSecurityConfig")
    if debuggable is True:
        findings.append(Finding(finding_id="MAK-APK-DEBUGGABLE", module="apk-config", package=package, title="Application is explicitly debuggable", description="android:debuggable=true is set on the application element.", severity=Severity.HIGH, confidence=Confidence.CONFIRMED, evidence={"android:debuggable": True}, owasp_mobile_top10=["M7", "M8"], masvs=["MASVS-CODE-2", "MASVS-RESILIENCE-2"], remediation="Build production variants with debugging disabled."))
    if allow_backup is True:
        findings.append(Finding(finding_id="MAK-APK-BACKUP", module="apk-config", package=package, title="Application backup is enabled", description="android:allowBackup=true is set; backup exclusions and data sensitivity require review.", severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, evidence={"android:allowBackup": True, "fullBackupContent": app.attrib.get(f"{A}fullBackupContent"), "dataExtractionRules": app.attrib.get(f"{A}dataExtractionRules")}, owasp_mobile_top10=["M9", "M8"], masvs=["MASVS-STORAGE-2"], maswe=["MASWE-0006"], mastg=["MASTG-TEST-0216", "MASTG-TEST-0262"], remediation="Define and test backup/data-extraction rules that exclude sensitive data."))
    if cleartext is True:
        findings.append(Finding(finding_id="MAK-APK-CLEARTEXT", module="apk-config", package=package, title="Manifest explicitly permits cleartext traffic", description="android:usesCleartextTraffic=true is set; Network Security Configuration may further refine behavior.", severity=Severity.HIGH, confidence=Confidence.CONFIRMED, evidence={"android:usesCleartextTraffic": True, "networkSecurityConfig": network_config}, owasp_mobile_top10=["M5", "M8"], masvs=["MASVS-NETWORK-1"], maswe=["MASWE-0050"], mastg=["MASTG-TEST-0235"], cwe=["CWE-319"], remediation="Disable cleartext traffic and use narrowly scoped exceptions only when necessary."))
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for component in app.findall(tag):
            if _bool(component.attrib.get(f"{A}exported")) is not True:
                continue
            permission = component.attrib.get(f"{A}permission") or app.attrib.get(f"{A}permission")
            if permission:
                continue
            name = component.attrib.get(f"{A}name", "<unknown>")
            suffix = hashlib.sha256(name.encode()).hexdigest()[:8].upper()
            findings.append(Finding(finding_id=f"MAK-APK-EXPORTED-{tag.upper()}-{suffix}", module="apk-config", package=package, title=f"Exported {tag} without component/application permission", description="An exported component lacks an explicit component/application permission; application logic still requires manual authorization review.", severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, evidence={"component_type": tag, "component_name": name, "exported": True}, owasp_mobile_top10=["M4", "M8"], masvs=["MASVS-PLATFORM-1"], remediation="Minimize exported components and enforce permissions plus in-component authorization."))
    sdk = root.find("uses-sdk")
    findings.append(Finding(finding_id="MAK-APK-METADATA", module="apk-config", package=package, title="APK manifest security metadata collected", description="Manifest metadata was parsed without executing application code.", severity=Severity.INFO, confidence=Confidence.CONFIRMED, evidence={"package": package, "networkSecurityConfig": network_config, "targetSdkVersion": sdk.attrib.get(f"{A}targetSdkVersion") if sdk is not None else None, "minSdkVersion": sdk.attrib.get(f"{A}minSdkVersion") if sdk is not None else None}, owasp_mobile_top10=["M8"], masvs=["MASVS-CODE-1"]))
    return findings


def inspect_apk(apk_path: Path) -> list[Finding]:
    if not apk_path.is_file():
        raise FileNotFoundError(apk_path)
    tool = shutil.which("apkanalyzer")
    if not tool:
        raise RuntimeError("apkanalyzer not found. Install Android SDK tooling and add it to PATH.")
    result = subprocess.run([tool, "manifest", "print", str(apk_path)], check=True, capture_output=True, text=True, timeout=30)
    return parse_manifest_xml(result.stdout)
