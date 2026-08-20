from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from typing import Any

from mobileauditkit.models import AssessmentStatus, Confidence, Severity, StaticAnalysisResult
from mobileauditkit.static_support import (
    _DANGEROUS_PERMISSIONS,
    A,
    _append,
    _bool,
    _component_name,
    _finding,
    _has_launcher_or_browsable,
    _int,
    _resource_path,
)
from mobileauditkit.test_registry import get_test


def analyze_manifest_xml(
    xml_text: str,
    *,
    resource_xml: dict[str, str] | None = None,
) -> StaticAnalysisResult:
    resource_xml = resource_xml or {}
    root = ET.fromstring(xml_text)
    app = root.find("application")
    package = root.attrib.get("package")
    output = StaticAnalysisResult(metadata={"package": package})
    if app is None:
        return output

    test = get_test("MAK-AND-0001")
    debuggable = _bool(app.attrib.get(f"{A}debuggable"))
    finding = None
    status = AssessmentStatus.PASS
    if debuggable is True:
        status = AssessmentStatus.FAIL
        finding = _finding(test, "MAK-APK-DEBUGGABLE", "Application is explicitly debuggable", "android:debuggable=true is set on the application element.", Severity.HIGH, package, {"android:debuggable": True}, remediation="Build production variants with debugging disabled.")
    _append(output, test, status, f"android:debuggable={debuggable}", "FAIL when the final production manifest is explicitly debuggable; otherwise PASS for this manifest check.", evidence_data={"android:debuggable": debuggable}, evidence_type="manifest", source="AndroidManifest.xml", finding=finding)

    test = get_test("MAK-AND-0002")
    cleartext = _bool(app.attrib.get(f"{A}usesCleartextTraffic"))
    network_ref = app.attrib.get(f"{A}networkSecurityConfig")
    finding = None
    if cleartext is True:
        status = AssessmentStatus.FAIL
        finding = _finding(test, "MAK-APK-CLEARTEXT", "Manifest explicitly permits cleartext traffic", "android:usesCleartextTraffic=true is set.", Severity.HIGH, package, {}, remediation="Disable cleartext traffic and use narrowly scoped exceptions only when required.")
    elif network_ref:
        status = AssessmentStatus.INCONCLUSIVE
    else:
        status = AssessmentStatus.PASS
    _append(output, test, status, f"usesCleartextTraffic={cleartext}; networkSecurityConfig={network_ref or 'none'}", "Network Security Configuration is evaluated separately when declared.", evidence_data={"android:usesCleartextTraffic": cleartext, "networkSecurityConfig": network_ref}, evidence_type="manifest", source="AndroidManifest.xml", finding=finding)

    test = get_test("MAK-AND-0003")
    allow_backup = _bool(app.attrib.get(f"{A}allowBackup"))
    full_backup = app.attrib.get(f"{A}fullBackupContent")
    extraction = app.attrib.get(f"{A}dataExtractionRules")
    refs = [ref for ref in (full_backup, extraction) if ref]
    resolved = [resource_xml.get(_resource_path(ref) or "") for ref in refs]
    finding = None
    if allow_backup is False:
        status = AssessmentStatus.PASS
        observation = "Application backup is explicitly disabled."
    elif allow_backup is True and not refs:
        status = AssessmentStatus.FAIL
        observation = "Backup is enabled without declared backup/data-extraction rules."
        finding = _finding(test, "MAK-APK-BACKUP", "Application backup is enabled", "android:allowBackup=true is set without an explicit backup exclusion resource.", Severity.MEDIUM, package, {}, remediation="Define and test backup/data-extraction rules that exclude sensitive data.")
    elif refs and any(resolved):
        has_exclude = any("<exclude" in text for text in resolved if text)
        status = AssessmentStatus.PASS if has_exclude else AssessmentStatus.INCONCLUSIVE
        observation = "Backup rule resource(s) resolved; exclusion directives were found." if has_exclude else "Backup rule resource(s) resolved but no exclusion directive was observed."
    else:
        status = AssessmentStatus.INCONCLUSIVE
        observation = "Backup configuration requires resource-level review."
    _append(output, test, status, observation, "PASS only when backup is disabled or resolved rules demonstrate exclusions; unresolved/contextual cases remain INCONCLUSIVE.", evidence_data={"android:allowBackup": allow_backup, "fullBackupContent": full_backup, "dataExtractionRules": extraction, "resolved_rule_count": sum(bool(x) for x in resolved)}, evidence_type="manifest+resource", source="AndroidManifest.xml", finding=finding)

    test = get_test("MAK-AND-0004")
    exported: list[dict[str, Any]] = []
    concerning: list[dict[str, Any]] = []
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for component in app.findall(tag):
            if _bool(component.attrib.get(f"{A}exported")) is not True:
                continue
            item = {"type": tag, "name": _component_name(component), "permission": component.attrib.get(f"{A}permission") or app.attrib.get(f"{A}permission"), "public_entry_point": tag.startswith("activity") and _has_launcher_or_browsable(component)}
            exported.append(item)
            if not item["permission"] and not item["public_entry_point"]:
                concerning.append(item)
    if concerning:
        status = AssessmentStatus.INCONCLUSIVE
        observation = f"{len(concerning)} exported component(s) lack manifest-level permission protection and require code-level sensitivity/authorization validation."
        for item in concerning:
            suffix = hashlib.sha256(f"{item['type']}:{item['name']}".encode()).hexdigest()[:8].upper()
            output.findings.append(_finding(test, f"MAK-APK-EXPORTED-{item['type'].upper()}-{suffix}", f"Exported {item['type']} requires access-control review", "Manifest exposure is observed, but sensitive functionality and in-component authorization require code/runtime validation.", Severity.LOW, package, item, confidence=Confidence.OBSERVED, remediation="Minimize exported components and enforce appropriate permission and in-component authorization controls."))
    else:
        status = AssessmentStatus.PASS
        observation = f"Inventoried {len(exported)} exported component(s); no non-entry component lacking a manifest permission was observed."
    _append(output, test, status, observation, "Manifest exposure alone is not treated as a confirmed vulnerability; code-sensitive cases remain INCONCLUSIVE.", evidence_data={"exported_components": exported, "requires_review": concerning}, evidence_type="manifest", source="AndroidManifest.xml")
    if concerning:
        evid = output.evidence[-1]
        for finding in [x for x in output.findings if x.test_id == test.test_id and not x.evidence_ids]:
            finding.evidence_ids = [evid.evidence_id]
            finding.evidence = {"component_type": finding.evidence.get("type"), "component_name": finding.evidence.get("name"), "exported": True}
        output.tests[-1].finding_ids = [x.finding_id for x in output.findings if x.test_id == test.test_id]

    test = get_test("MAK-AND-0005")
    perms = []
    weak = []
    for permission in root.findall("permission"):
        name = permission.attrib.get(f"{A}name", "<unknown>")
        level = permission.attrib.get(f"{A}protectionLevel", "normal")
        item = {"name": name, "protectionLevel": level}
        perms.append(item)
        if not any(strong in level for strong in ("signature", "knownSigner")):
            weak.append(item)
    status = AssessmentStatus.INCONCLUSIVE if weak else AssessmentStatus.PASS
    _append(output, test, status, f"Inventoried {len(perms)} custom permission(s); {len(weak)} use a non-signature trust level.", "Non-signature custom permissions require contextual review of the exposed capability.", evidence_data={"custom_permissions": perms, "requires_review": weak}, evidence_type="manifest", source="AndroidManifest.xml")

    test = get_test("MAK-AND-0006")
    links: list[dict[str, Any]] = []
    for activity in app.findall("activity"):
        for intent in activity.findall("intent-filter"):
            categories = {x.attrib.get(f"{A}name") for x in intent.findall("category")}
            if "android.intent.category.BROWSABLE" not in categories:
                continue
            for data in intent.findall("data"):
                links.append({"activity": _component_name(activity), "scheme": data.attrib.get(f"{A}scheme"), "host": data.attrib.get(f"{A}host"), "autoVerify": intent.attrib.get(f"{A}autoVerify")})
    if any(item["scheme"] == "http" for item in links):
        status = AssessmentStatus.FAIL
    elif any(item["scheme"] and item["scheme"] not in {"https"} for item in links):
        status = AssessmentStatus.INCONCLUSIVE
    else:
        status = AssessmentStatus.PASS
    finding = _finding(test, "MAK-APK-DEEPLINK-HTTP", "Cleartext HTTP deep link declared", "A browsable intent filter declares the http scheme.", Severity.MEDIUM, package, {}, remediation="Prefer verified HTTPS App Links for web-origin navigation.") if status == AssessmentStatus.FAIL else None
    _append(output, test, status, f"Inventoried {len(links)} browsable deep-link declaration(s).", "HTTP deep links FAIL; custom schemes remain INCONCLUSIVE because routing/security depends on application logic.", evidence_data={"deep_links": links}, evidence_type="manifest", source="AndroidManifest.xml", finding=finding)

    test = get_test("MAK-AND-0007")
    network_path = _resource_path(network_ref)
    network_xml = resource_xml.get(network_path or "") if network_path else None
    finding = None
    if not network_ref:
        status = AssessmentStatus.PASS
        observation = "No custom Network Security Configuration was declared."
        data = {"declared": False}
    elif not network_xml:
        status = AssessmentStatus.INCONCLUSIVE
        observation = "Network Security Configuration was declared but could not be resolved."
        data = {"declared": True, "resource": network_path, "resolved": False}
    else:
        nroot = ET.fromstring(network_xml)
        clear_nodes = [node for node in nroot.iter() if node.tag != "debug-overrides" and node.attrib.get("cleartextTrafficPermitted", "false").lower() == "true"]
        debug_ids = {id(node) for debug in nroot.findall("debug-overrides") for node in debug.iter()}
        user_cas = [node for node in nroot.iter("certificates") if id(node) not in debug_ids and node.attrib.get("src") == "user"]
        insecure = bool(clear_nodes or user_cas)
        status = AssessmentStatus.FAIL if insecure else AssessmentStatus.PASS
        observation = f"Resolved Network Security Configuration; cleartext-enabled nodes={len(clear_nodes)}, production user-CA anchors={len(user_cas)}."
        data = {"declared": True, "resource": network_path, "resolved": True, "cleartext_enabled_nodes": len(clear_nodes), "production_user_ca_anchors": len(user_cas)}
        if insecure:
            finding = _finding(test, "MAK-APK-NETWORK-SECURITY-CONFIG", "Network Security Configuration weakens production transport trust", "Production Network Security Configuration permits cleartext traffic and/or trusts user-added certificate authorities.", Severity.HIGH, package, {}, remediation="Disable production cleartext and restrict trust anchors to the required CA set; keep debug-only trust under debug-overrides.")
    _append(output, test, status, observation, "FAIL for production cleartext or user-added CA trust; unresolved resources are INCONCLUSIVE.", evidence_data=data, evidence_type="network-security-config", source=network_path or "AndroidManifest.xml", finding=finding)

    test = get_test("MAK-AND-0008")
    providers = [p for p in app.findall("provider") if _component_name(p).endswith("FileProvider") or "fileprovider" in _component_name(p).lower()]
    exported_fileproviders = [_component_name(p) for p in providers if _bool(p.attrib.get(f"{A}exported")) is True]
    status = AssessmentStatus.FAIL if exported_fileproviders else AssessmentStatus.PASS
    finding = _finding(test, "MAK-APK-FILEPROVIDER-EXPORTED", "FileProvider is exported", "A FileProvider declaration is explicitly exported.", Severity.HIGH, package, {}, remediation="Set FileProvider android:exported=false and grant URI permissions narrowly.") if exported_fileproviders else None
    _append(output, test, status, f"FileProvider declarations={len(providers)}; exported={len(exported_fileproviders)}.", "FileProvider should not be directly exported.", evidence_data={"fileproviders": [_component_name(p) for p in providers], "exported": exported_fileproviders}, evidence_type="manifest", source="AndroidManifest.xml", finding=finding)

    test = get_test("MAK-AND-0009")
    sdk = root.find("uses-sdk")
    target = _int(sdk.attrib.get(f"{A}targetSdkVersion")) if sdk is not None else None
    minimum = int(test.parameters.get("minimum_target_sdk", 35))
    finding = None
    if target is None:
        status = AssessmentStatus.INCONCLUSIVE
    elif target < minimum:
        status = AssessmentStatus.FAIL
        finding = _finding(test, "MAK-APK-TARGET-SDK", "Target SDK is below the reviewed security baseline", f"targetSdkVersion={target} is below the registry-reviewed baseline {minimum}.", Severity.MEDIUM, package, {}, remediation="Review platform behavior changes and target a currently supported Android API level.")
    else:
        status = AssessmentStatus.PASS
    _append(output, test, status, f"targetSdkVersion={target}; reviewed minimum={minimum}.", "Registry baseline is versioned and should be periodically reviewed rather than treated as a permanent compliance threshold.", evidence_data={"targetSdkVersion": target, "minimum_target_sdk": minimum}, evidence_type="manifest", source="AndroidManifest.xml", finding=finding)

    test = get_test("MAK-AND-0010")
    requested = sorted({p.attrib.get(f"{A}name") for p in root.findall("uses-permission") if p.attrib.get(f"{A}name") in _DANGEROUS_PERMISSIONS})
    _append(output, test, AssessmentStatus.PASS, f"Inventoried {len(requested)} security/privacy-sensitive permission(s).", "PASS means inventory collection completed; necessity and consent require contextual review.", evidence_data={"permissions": requested}, evidence_type="manifest", source="AndroidManifest.xml")

    output.metadata.update({"package": package, "versionCode": root.attrib.get(f"{A}versionCode"), "versionName": root.attrib.get(f"{A}versionName"), "targetSdkVersion": target})
    return output
