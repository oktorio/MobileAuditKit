from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from mobileauditkit.evidence import make_evidence
from mobileauditkit.models import (
    AssessmentStatus,
    AtomicTestResult,
    Confidence,
    Finding,
    Severity,
    StaticAnalysisResult,
)
from mobileauditkit.test_registry import TestDefinition

ANDROID_NS = "http://schemas.android.com/apk/res/android"
A = f"{{{ANDROID_NS}}}"

_DANGEROUS_PERMISSIONS = {
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.CAMERA",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
}


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    return True if lowered == "true" else False if lowered == "false" else None


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _resource_path(reference: str | None) -> str | None:
    if not reference or not reference.startswith("@xml/"):
        return None
    return f"/res/xml/{reference.split('/', 1)[1]}.xml"


def _result(test: TestDefinition, status: AssessmentStatus, observation: str, evaluation: str, *, evidence_ids: list[str] | None = None, finding_ids: list[str] | None = None, severity: Severity | None = None) -> AtomicTestResult:
    return AtomicTestResult(test_id=test.test_id, title=test.title, module=test.module, engine=test.engine, status=status, observation=observation, evaluation=evaluation, severity=severity, evidence_ids=evidence_ids or [], finding_ids=finding_ids or [], owasp_mobile_top10=test.owasp_mobile_top10, masvs=test.masvs, maswe=test.maswe, mastg=test.mastg, cwe=test.cwe)


def _finding(test: TestDefinition, finding_id: str, title: str, description: str, severity: Severity, package: str | None, evidence: dict[str, Any], *, confidence: Confidence = Confidence.CONFIRMED, remediation: str | None = None) -> Finding:
    return Finding(finding_id=finding_id, title=title, description=description, severity=severity, confidence=confidence, module="apk-config", test_id=test.test_id, package=package, evidence=evidence, owasp_mobile_top10=test.owasp_mobile_top10, masvs=test.masvs, maswe=test.maswe, mastg=test.mastg, cwe=test.cwe, remediation=remediation, references=test.references)


def _append(output: StaticAnalysisResult, test: TestDefinition, status: AssessmentStatus, observation: str, evaluation: str, *, evidence_data: dict[str, Any], evidence_type: str, source: str, finding: Finding | None = None, severity: Severity | None = None) -> None:
    record = make_evidence(source=source, module="apk-config", test_id=test.test_id, evidence_type=evidence_type, data=evidence_data)
    output.evidence.append(record)
    finding_ids: list[str] = []
    if finding:
        finding.evidence_ids = [record.evidence_id]
        finding.evidence = record.data
        output.findings.append(finding)
        finding_ids.append(finding.finding_id)
    output.tests.append(_result(test, status, observation, evaluation, evidence_ids=[record.evidence_id], finding_ids=finding_ids, severity=severity or (finding.severity if finding else None)))


def _has_launcher_or_browsable(component: ET.Element) -> bool:
    for intent in component.findall("intent-filter"):
        actions = {x.attrib.get(f"{A}name") for x in intent.findall("action")}
        categories = {x.attrib.get(f"{A}name") for x in intent.findall("category")}
        if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
            return True
        if "android.intent.category.BROWSABLE" in categories:
            return True
    return False


def _component_name(component: ET.Element) -> str:
    return component.attrib.get(f"{A}name", "<unknown>")
