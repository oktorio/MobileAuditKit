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

    sdk = root.find("uses-sdk")
    target = _int(sdk.attrib.get(f"{A}targetSdkVersion")) if sdk is not None else None

    test = get_test("MAK-AND-0002")
    cleartext_raw = app.attrib.get(f"{A}usesCleartextTraffic")
    cleartext = _bool(cleartext_raw)
    network_ref = app.attrib.get(f"{A}networkSecurityConfig")
    effective_default = None if target is None else target <= 27
    finding = None
    if network_ref:
        status = AssessmentStatus.INCONCLUSIVE
        observation = "Network Security Configuration is declared; effective cleartext policy is evaluated from that resource."
    elif cleartext is True or (cleartext_raw is None and effective_default is True):
        status = AssessmentStatus.FAIL
        source_text = "explicitly permits" if cleartext is True else "inherits the target-SDK default permitting"
        observation = f"Application {source_text} cleartext traffic."
        finding = _finding(test, "MAK-APK-CLEARTEXT", "Effective manifest policy permits cleartext traffic", observation, Severity.HIGH, package, {}, remediation="Disable cleartext traffic and use narrowly scoped Network Security Configuration exceptions only when required.")
    elif cleartext is False or (cleartext_raw is None and effective_default is False):
        status = AssessmentStatus.PASS
        observation = "Effective manifest cleartext policy is disabled."
    else:
        status = AssessmentStatus.INCONCLUSIVE
        observation = "Cleartext attribute is absent and targetSdkVersion is unresolved, so the effective platform default cannot be established."
    _append(output, test, status, observation, "Use the effective Android policy: target SDK 27 and lower default to cleartext permitted; target SDK 28+ default to denied unless Network Security Configuration changes the policy.", evidence_data={"android:usesCleartextTraffic": cleartext, "attribute_present": cleartext_raw is not None, "networkSecurityConfig": network_ref, "targetSdkVersion": target, "effective_default_cleartext": effective_default}, evidence_type="manifest", source="AndroidManifest.xml", finding=finding)

    test = get_test("MAK-AND-0003")
    allow_backup_raw = app.attrib.get(f"{A}allowBackup")
    allow_backup = _bool(allow_backup_raw)
    full_backup = app.attrib.get(f"{A}fullBackupContent")
    extraction = app.attrib.get(f"{A}dataExtractionRules")
    refs = [ref for ref in (full_backup, extraction) if ref]
    resolved_pairs = [
        (ref, resource_xml.get(_resource_path(ref) or ""))
        for ref in refs
    ]
    finding = None
    backup_evidence: dict[str, Any] = {
        "android:allowBackup": allow_backup,
        "allowBackup_attribute_present": allow_backup_raw is not None,
        "fullBackupContent": full_backup,
        "dataExtractionRules": extraction,
        "resolved_rule_count": sum(bool(text) for _, text in resolved_pairs),
        "targetSdkVersion": target,
    }
    if allow_backup is False:
        status = AssessmentStatus.PASS
        observation = "Application backup is explicitly disabled."
    elif not refs:
        if allow_backup is True:
            status = AssessmentStatus.FAIL
            observation = "Backup is enabled without declared backup/data-extraction rules."
            finding = _finding(
                test,
                "MAK-APK-BACKUP",
                "Application backup is enabled",
                observation,
                Severity.MEDIUM,
                package,
                {},
                remediation="Define and test backup/data-extraction rules that exclude sensitive data, or disable backup when it is not required.",
            )
        else:
            status = AssessmentStatus.INCONCLUSIVE
            observation = (
                "Backup attributes are omitted and no rule resource is declared; protection of "
                "sensitive data cannot be established from the manifest alone."
            )
    elif not all(text for _, text in resolved_pairs):
        status = AssessmentStatus.INCONCLUSIVE
        observation = "One or more declared backup/data-extraction rule resources could not be resolved."
    else:
        parsed_resources: list[dict[str, Any]] = []
        parse_failed = False
        for ref, text in resolved_pairs:
            assert text is not None
            try:
                rroot = ET.fromstring(text)
            except ET.ParseError:
                parse_failed = True
                continue
            entry: dict[str, Any] = {
                "reference": ref,
                "root": rroot.tag,
                "sections": {},
            }
            if rroot.tag == "full-backup-content":
                nodes = list(rroot)
                entry["sections"]["legacy-auto-backup"] = [
                    {
                        "kind": node.tag,
                        "domain": node.attrib.get("domain"),
                        "path": node.attrib.get("path", "."),
                    }
                    for node in nodes
                    if node.tag in {"include", "exclude"}
                ]
            elif rroot.tag == "data-extraction-rules":
                for section_name in ("cloud-backup", "device-transfer"):
                    section = rroot.find(section_name)
                    entry["sections"][section_name] = [
                        {
                            "kind": node.tag,
                            "domain": node.attrib.get("domain"),
                            "path": node.attrib.get("path", "."),
                        }
                        for node in list(section) if node.tag in {"include", "exclude"}
                    ] if section is not None else []
            else:
                entry["unknown_root"] = True
            parsed_resources.append(entry)

        backup_evidence["resources"] = parsed_resources
        required_domains = {"root", "file", "database", "sharedpref", "external"}

        def section_is_comprehensive(rules: list[dict[str, Any]]) -> bool:
            included = {
                str(rule["domain"])
                for rule in rules
                if rule["kind"] == "include"
            }
            excluded_roots = {
                str(rule["domain"])
                for rule in rules
                if rule["kind"] == "exclude" and rule["path"] in {".", ""}
            }
            return not included and required_domains.issubset(excluded_roots)

        comprehensive = False
        if not parse_failed:
            if target is not None and target >= 31 and extraction:
                modern = next(
                    (
                        item for item in parsed_resources
                        if item["root"] == "data-extraction-rules"
                    ),
                    None,
                )
                if modern is not None:
                    comprehensive = all(
                        section_is_comprehensive(modern["sections"].get(section, []))
                        for section in ("cloud-backup", "device-transfer")
                    )
            elif target is not None and target <= 30 and full_backup:
                legacy = next(
                    (
                        item for item in parsed_resources
                        if item["root"] == "full-backup-content"
                    ),
                    None,
                )
                if legacy is not None:
                    comprehensive = section_is_comprehensive(
                        legacy["sections"].get("legacy-auto-backup", [])
                    )

        backup_evidence["comprehensive_exclusion"] = comprehensive
        if parse_failed:
            status = AssessmentStatus.INCONCLUSIVE
            observation = "One or more backup rule resources could not be parsed structurally."
        elif comprehensive:
            status = AssessmentStatus.PASS
            observation = (
                "Applicable backup rules structurally exclude all standard app-data domains "
                "for the relevant backup/transfer paths."
            )
        else:
            status = AssessmentStatus.INCONCLUSIVE
            observation = (
                "Backup rules were parsed by domain/path and transport, but protection of "
                "sensitive data cannot be established comprehensively."
            )
    _append(
        output,
        test,
        status,
        observation,
        "PASS only when backup is disabled or the applicable SDK-era rules comprehensively exclude standard data domains across the relevant cloud/device-transfer paths; unresolved or partial protection remains INCONCLUSIVE.",
        evidence_data=backup_evidence,
        evidence_type="manifest+resource",
        source="AndroidManifest.xml",
        finding=finding,
    )

    test = get_test("MAK-AND-0004")
    exported: list[dict[str, Any]] = []
    concerning: list[dict[str, Any]] = []
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for component in app.findall(tag):
            exported_raw = component.attrib.get(f"{A}exported")
            exported_value = _bool(exported_raw)
            if exported_value is None:
                has_filter = bool(component.findall("intent-filter"))
                if tag == "provider":
                    exported_value = target is not None and target <= 16
                else:
                    exported_value = has_filter if target is not None and target <= 30 else False
            if exported_value is not True:
                continue
            component_name = _component_name(component)
            component_permission = component.attrib.get(f"{A}permission") or app.attrib.get(f"{A}permission")
            public_entry_point = tag.startswith("activity") and _has_launcher_or_browsable(component)
            item: dict[str, Any] = {
                "type": tag,
                "name": component_name,
                "permission": component_permission,
                "public_entry_point": public_entry_point,
            }
            exported.append(item)
            if not component_permission and not public_entry_point:
                concerning.append(item)
    if concerning:
        status = AssessmentStatus.INCONCLUSIVE
        observation = f"{len(concerning)} exported component(s) lack manifest-level permission protection and require code-level sensitivity/authorization validation."
        for item in concerning:
            component_type = str(item["type"])
            component_name = str(item["name"])
            suffix = hashlib.sha256(f"{component_type}:{component_name}".encode()).hexdigest()[:8].upper()
            output.findings.append(_finding(test, f"MAK-APK-EXPORTED-{component_type.upper()}-{suffix}", f"Exported {component_type} requires access-control review", "Manifest exposure is observed, but sensitive functionality and in-component authorization require code/runtime validation.", Severity.LOW, package, item, confidence=Confidence.OBSERVED, remediation="Minimize exported components and enforce appropriate permission and in-component authorization controls."))
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
    perms: list[dict[str, str]] = []
    weak: list[dict[str, str]] = []
    for permission in root.findall("permission"):
        name = permission.attrib.get(f"{A}name", "<unknown>")
        level = permission.attrib.get(f"{A}protectionLevel")
        effective_level = level or "normal"
        permission_item = {"name": name, "protectionLevel": effective_level, "attribute_present": level is not None}
        perms.append(permission_item)
        base_level = effective_level.split("|", 1)[0]
        if base_level not in {"signature", "knownSigner"}:
            weak.append(permission_item)
    status = AssessmentStatus.INCONCLUSIVE if weak else AssessmentStatus.PASS
    _append(output, test, status, f"Inventoried {len(perms)} custom permission(s); {len(weak)} use a non-signature trust level.", "Non-signature custom permissions require contextual review of the exposed capability.", evidence_data={"custom_permissions": perms, "requires_review": weak}, evidence_type="manifest", source="AndroidManifest.xml")

    test = get_test("MAK-AND-0006")
    links: list[dict[str, Any]] = []
    for activity in app.findall("activity"):
        for intent in activity.findall("intent-filter"):
            categories = {x.attrib.get(f"{A}name") for x in intent.findall("category")}
            if "android.intent.category.BROWSABLE" not in categories:
                continue
            for data_node in intent.findall("data"):
                links.append({"activity": _component_name(activity), "scheme": data_node.attrib.get(f"{A}scheme"), "host": data_node.attrib.get(f"{A}host"), "autoVerify": intent.attrib.get(f"{A}autoVerify")})
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
    network_data: dict[str, Any]
    platform_cleartext = None if target is None else target <= 27
    platform_user_ca = None if target is None else target <= 23
    if not network_ref:
        if target is None:
            status = AssessmentStatus.INCONCLUSIVE
            observation = "No custom Network Security Configuration was declared and targetSdkVersion is unresolved."
        else:
            insecure_default = bool(platform_cleartext or platform_user_ca)
            status = AssessmentStatus.FAIL if insecure_default else AssessmentStatus.PASS
            observation = (
                "No custom Network Security Configuration was declared; effective platform defaults "
                f"are cleartext={platform_cleartext}, user-CA-trust={platform_user_ca}."
            )
            if insecure_default:
                finding = _finding(
                    test,
                    "MAK-APK-NETWORK-DEFAULTS",
                    "Effective Android network defaults weaken production transport policy",
                    observation,
                    Severity.HIGH,
                    package,
                    {},
                    remediation="Use a current target SDK and explicitly constrain production network trust where required.",
                )
        network_data = {
            "declared": False,
            "targetSdkVersion": target,
            "effective_default_cleartext": platform_cleartext,
            "effective_default_user_ca_trust": platform_user_ca,
        }
    elif not network_xml:
        status = AssessmentStatus.INCONCLUSIVE
        observation = "Network Security Configuration was declared but could not be resolved."
        network_data = {"declared": True, "resource": network_path, "resolved": False}
    else:
        nroot = ET.fromstring(network_xml)
        debug_ids = {
            id(node)
            for debug in nroot.findall("debug-overrides")
            for node in debug.iter()
        }

        base = nroot.find("base-config")
        base_cleartext = platform_cleartext
        if base is not None and "cleartextTrafficPermitted" in base.attrib:
            base_cleartext = _bool(base.attrib.get("cleartextTrafficPermitted"))

        effective_cleartext: list[dict[str, Any]] = []
        if base_cleartext is True:
            effective_cleartext.append({"scope": "base", "inherited": base is None or "cleartextTrafficPermitted" not in base.attrib})

        def walk_domain(node: ET.Element, inherited: bool | None) -> None:
            current = inherited
            if "cleartextTrafficPermitted" in node.attrib:
                current = _bool(node.attrib.get("cleartextTrafficPermitted"))
            domains = [item.text or "" for item in node.findall("domain")]
            if current is True:
                effective_cleartext.append(
                    {
                        "scope": "domain",
                        "domains": domains,
                        "inherited": "cleartextTrafficPermitted" not in node.attrib,
                    }
                )
            for child in node.findall("domain-config"):
                walk_domain(child, current)

        for domain_config in nroot.findall("domain-config"):
            walk_domain(domain_config, base_cleartext)

        user_cas = [
            node
            for node in nroot.iter("certificates")
            if id(node) not in debug_ids and node.attrib.get("src") == "user"
        ]
        unresolved_inheritance = target is None and (
            (base is None or "cleartextTrafficPermitted" not in base.attrib)
            or not list(nroot.iter("trust-anchors"))
        )
        insecure = bool(effective_cleartext or user_cas)
        if insecure:
            status = AssessmentStatus.FAIL
        elif unresolved_inheritance:
            status = AssessmentStatus.INCONCLUSIVE
        else:
            status = AssessmentStatus.PASS
        observation = (
            "Resolved Network Security Configuration with inherited policy; "
            f"effective cleartext scopes={len(effective_cleartext)}, "
            f"production user-CA anchors={len(user_cas)}."
        )
        network_data = {
            "declared": True,
            "resource": network_path,
            "resolved": True,
            "targetSdkVersion": target,
            "effective_cleartext_scopes": effective_cleartext,
            "production_user_ca_anchors": len(user_cas),
            "unresolved_inheritance": unresolved_inheritance,
        }
        if insecure:
            finding = _finding(
                test,
                "MAK-APK-NETWORK-SECURITY-CONFIG",
                "Network Security Configuration weakens production transport trust",
                "Effective production Network Security Configuration permits cleartext traffic and/or trusts user-added certificate authorities.",
                Severity.HIGH,
                package,
                {},
                remediation="Disable production cleartext and restrict trust anchors to the required CA set; keep debug-only trust under debug-overrides.",
            )
    _append(
        output,
        test,
        status,
        observation,
        "Evaluate effective inherited Network Security Configuration and target-SDK defaults; FAIL for production cleartext or user-added CA trust, and keep unresolved inheritance INCONCLUSIVE.",
        evidence_data=network_data,
        evidence_type="network-security-config",
        source=network_path or "AndroidManifest.xml",
        finding=finding,
    )

    test = get_test("MAK-AND-0008")
    providers = [p for p in app.findall("provider") if _component_name(p).endswith("FileProvider") or "fileprovider" in _component_name(p).lower()]
    exported_fileproviders = [_component_name(p) for p in providers if _bool(p.attrib.get(f"{A}exported")) is True]
    status = AssessmentStatus.FAIL if exported_fileproviders else AssessmentStatus.PASS
    finding = _finding(test, "MAK-APK-FILEPROVIDER-EXPORTED", "FileProvider is exported", "A FileProvider declaration is explicitly exported.", Severity.HIGH, package, {}, remediation="Set FileProvider android:exported=false and grant URI permissions narrowly.") if exported_fileproviders else None
    _append(output, test, status, f"FileProvider declarations={len(providers)}; exported={len(exported_fileproviders)}.", "FileProvider should not be directly exported.", evidence_data={"fileproviders": [_component_name(p) for p in providers], "exported": exported_fileproviders}, evidence_type="manifest", source="AndroidManifest.xml", finding=finding)

    test = get_test("MAK-AND-0009")
    minimum_raw = test.parameters.get("minimum_target_sdk", 35)
    minimum = int(minimum_raw) if isinstance(minimum_raw, (str, int)) else 35
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
    requested: list[str] = []
    for permission_node in root.findall("uses-permission"):
        permission_name = permission_node.attrib.get(f"{A}name")
        if permission_name is not None and permission_name in _DANGEROUS_PERMISSIONS:
            requested.append(permission_name)
    requested.sort()
    _append(output, test, AssessmentStatus.PASS, f"Inventoried {len(requested)} security/privacy-sensitive permission(s).", "PASS means inventory collection completed; necessity and consent require contextual review.", evidence_data={"permissions": requested}, evidence_type="manifest", source="AndroidManifest.xml")

    output.metadata.update({"package": package, "versionCode": root.attrib.get(f"{A}versionCode"), "versionName": root.attrib.get(f"{A}versionName"), "targetSdkVersion": target})
    return output
