from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mobileauditkit.event_parser import findings_from_events
from mobileauditkit.evidence import make_evidence
from mobileauditkit.models import (
    AssessmentStatus,
    AtomicTestResult,
    EvidenceRecord,
    Finding,
    HookHealth,
    HookHealthState,
    RuntimeAnalysisResult,
    Severity,
)
from mobileauditkit.test_registry import TestDefinition, tests_for_module


def _definition(module: str, test_id: str) -> TestDefinition:
    for item in tests_for_module(module, engine="dynamic"):
        if item.test_id == test_id:
            return item
    raise ValueError(f"Atomic runtime test {test_id} is not registered for module {module}")


def _result(
    definition: TestDefinition,
    status: AssessmentStatus,
    observation: str,
    evaluation: str,
    *,
    evidence_ids: list[str],
    finding_ids: list[str] | None = None,
    severity: Severity | None = None,
) -> AtomicTestResult:
    return AtomicTestResult(
        test_id=definition.test_id,
        title=definition.title,
        module=definition.module,
        engine=definition.engine,
        status=status,
        observation=observation,
        evaluation=evaluation,
        severity=severity,
        evidence_ids=list(dict.fromkeys(evidence_ids)),
        finding_ids=list(dict.fromkeys(finding_ids or [])),
        owasp_mobile_top10=definition.owasp_mobile_top10,
        masvs=definition.masvs,
        maswe=definition.maswe,
        mastg=definition.mastg,
        cwe=definition.cwe,
    )


def _health_ready(health: HookHealth) -> bool:
    return (
        health.script_loaded
        and health.signal_received
        and health.state == HookHealthState.READY
        and health.hooks_installed > 0
    )


def _event_kind(event: dict[str, Any]) -> str:
    return str(event.get("event", "runtime_observation"))


def _event_ids(
    events: list[dict[str, Any]],
    evidence: list[EvidenceRecord],
    predicate: Callable[[dict[str, Any]], bool],
) -> list[str]:
    return [
        record.evidence_id
        for event, record in zip(events, evidence, strict=True)
        if predicate(event)
    ]


def _finding_test_id(event: dict[str, Any]) -> str | None:
    kind = _event_kind(event)
    if kind == "crypto_algorithm":
        upper = str(event.get("algorithm", "")).upper().strip()
        if upper in {"MD5", "SHA-1", "SHA1"}:
            return "MAK-DYN-0201"
        weak_symmetric = (
            upper == "AES"
            or (not upper.startswith("RSA/") and "/ECB" in upper)
            or upper.startswith("DES")
            or "3DES" in upper
        )
        if weak_symmetric:
            return "MAK-DYN-0202"
        return None
    return {
        "storage_external": "MAK-DYN-0210",
        "storage_shared_preferences": "MAK-DYN-0211",
        "storage_file": "MAK-DYN-0211",
        "storage_database": "MAK-DYN-0211",
        "network_cleartext": "MAK-DYN-0220",
        "network_tls_context": "MAK-DYN-0221",
        "network_trust_manager": "MAK-DYN-0221",
        "network_hostname_verifier": "MAK-DYN-0221",
        "network_pinning": "MAK-DYN-0222",
        "biometric_authentication": "MAK-DYN-0230",
        "webview_snapshot": "MAK-DYN-0240",
        "webview_debugging": "MAK-DYN-0241",
        "webview_javascript_interface": "MAK-DYN-0242",
        "privacy_clipboard_write": "MAK-DYN-0250",
        "privacy_log_call": "MAK-DYN-0251",
        "privacy_flag_secure": "MAK-DYN-0252",
        "privacy_location_request": "MAK-DYN-0253",
        "resilience_root_check": "MAK-DYN-0260",
        "resilience_debug_check": "MAK-DYN-0261",
    }.get(kind)


def _failure_ids(findings: list[Finding], test_id: str) -> list[str]:
    return [finding.finding_id for finding in findings if finding.test_id == test_id]


def _absence_test(
    module: str,
    test_id: str,
    events: list[dict[str, Any]],
    event_evidence: list[EvidenceRecord],
    health: HookHealth,
    health_evidence_id: str,
    *,
    relevant: Callable[[dict[str, Any]], bool],
    failing: Callable[[dict[str, Any]], bool],
    findings: list[Finding],
    pass_text: str,
    fail_text: str,
) -> AtomicTestResult:
    definition = _definition(module, test_id)
    relevant_events = [event for event in events if relevant(event)]
    failing_events = [event for event in events if failing(event)]
    evidence_ids = [health_evidence_id, *_event_ids(events, event_evidence, relevant)]
    finding_ids = _failure_ids(findings, test_id)
    if failing_events:
        return _result(
            definition,
            AssessmentStatus.FAIL,
            f"Observed {len(failing_events)} failing event(s) among {len(relevant_events)} relevant runtime event(s).",
            fail_text,
            evidence_ids=evidence_ids,
            finding_ids=finding_ids,
            severity=definition.default_severity,
        )
    if _health_ready(health) and relevant_events:
        return _result(
            definition,
            AssessmentStatus.PASS,
            f"Observed {len(relevant_events)} relevant runtime event(s) with healthy hooks and no failing event.",
            pass_text,
            evidence_ids=evidence_ids,
        )
    reason = (
        "hook coverage was not fully healthy"
        if not _health_ready(health)
        else "the exercised flow produced no relevant API event"
    )
    return _result(
        definition,
        AssessmentStatus.INCONCLUSIVE,
        f"No failing event was observed, but {reason}.",
        "Negative runtime observation is insufficient for PASS without healthy hooks and relevant API activity.",
        evidence_ids=evidence_ids,
    )


def _positive_inventory_test(
    module: str,
    test_id: str,
    events: list[dict[str, Any]],
    event_evidence: list[EvidenceRecord],
    health_evidence_id: str,
    *,
    matching: Callable[[dict[str, Any]], bool],
    success_text: str,
    missing_text: str,
) -> AtomicTestResult:
    definition = _definition(module, test_id)
    matched = [event for event in events if matching(event)]
    evidence_ids = [health_evidence_id, *_event_ids(events, event_evidence, matching)]
    if matched:
        return _result(
            definition,
            AssessmentStatus.PASS,
            f"Observed {len(matched)} matching runtime event(s).",
            success_text,
            evidence_ids=evidence_ids,
        )
    return _result(
        definition,
        AssessmentStatus.INCONCLUSIVE,
        "The relevant runtime API was not observed in the exercised flow.",
        missing_text,
        evidence_ids=evidence_ids,
    )


def _evaluate_crypto(
    events: list[dict[str, Any]],
    evidence: list[EvidenceRecord],
    health: HookHealth,
    health_id: str,
    findings: list[Finding],
) -> list[AtomicTestResult]:
    def relevant(event: dict[str, Any]) -> bool:
        return _event_kind(event) == "crypto_algorithm"

    def weak_hash(event: dict[str, Any]) -> bool:
        return relevant(event) and str(event.get("algorithm", "")).upper() in {
            "MD5",
            "SHA-1",
            "SHA1",
        }

    def weak_cipher(event: dict[str, Any]) -> bool:
        if not relevant(event):
            return False
        algorithm = str(event.get("algorithm", "")).upper().strip()
        # MASTG-TEST-0232 concerns symmetric modes. Avoid false positives for
        # transformations such as RSA/ECB/OAEP, where ECB is only an API placeholder.
        if algorithm.startswith("RSA/"):
            return False
        if algorithm == "AES":
            return True  # Android/JCA defaults bare AES to ECB mode.
        return "/ECB" in algorithm or algorithm.startswith("DES") or "3DES" in algorithm

    return [
        _absence_test(
            "crypto",
            "MAK-DYN-0201",
            events,
            evidence,
            health,
            health_id,
            relevant=relevant,
            failing=weak_hash,
            findings=findings,
            pass_text="No deprecated hash algorithm was observed among the cryptographic API calls exercised in this flow.",
            fail_text="A deprecated hash algorithm was directly observed at runtime.",
        ),
        _absence_test(
            "crypto",
            "MAK-DYN-0202",
            events,
            evidence,
            health,
            health_id,
            relevant=relevant,
            failing=weak_cipher,
            findings=findings,
            pass_text="No DES/3DES/ECB-style encryption configuration was observed among the cryptographic API calls exercised in this flow.",
            fail_text="A weak or pattern-leaking encryption configuration was directly observed at runtime.",
        ),
    ]


def _evaluate_storage(
    events: list[dict[str, Any]],
    evidence: list[EvidenceRecord],
    health: HookHealth,
    health_id: str,
    findings: list[Finding],
) -> list[AtomicTestResult]:
    def storage(event: dict[str, Any]) -> bool:
        return _event_kind(event).startswith("storage_")

    def external(event: dict[str, Any]) -> bool:
        return _event_kind(event) == "storage_external"

    def local(event: dict[str, Any]) -> bool:
        return _event_kind(event) in {
            "storage_shared_preferences",
            "storage_file",
            "storage_database",
        }

    return [
        _absence_test(
            "storage",
            "MAK-DYN-0210",
            events,
            evidence,
            health,
            health_id,
            relevant=storage,
            failing=external,
            findings=findings,
            pass_text="No external/shared storage API was observed among storage operations exercised in this flow.",
            fail_text="An external/shared storage API was directly observed at runtime.",
        ),
        _positive_inventory_test(
            "storage",
            "MAK-DYN-0211",
            events,
            evidence,
            health_id,
            matching=local,
            success_text="Local storage API usage was inventoried without reading stored values.",
            missing_text="No conclusion about local storage behavior is made because no covered local-storage API was exercised.",
        ),
    ]


def _evaluate_network(
    events: list[dict[str, Any]],
    evidence: list[EvidenceRecord],
    health: HookHealth,
    health_id: str,
    findings: list[Finding],
) -> list[AtomicTestResult]:
    def network(event: dict[str, Any]) -> bool:
        return _event_kind(event).startswith("network_")

    def cleartext(event: dict[str, Any]) -> bool:
        return _event_kind(event) == "network_cleartext"

    def validation(event: dict[str, Any]) -> bool:
        return _event_kind(event) in {
            "network_tls_context",
            "network_trust_manager",
            "network_hostname_verifier",
        }

    def pinning(event: dict[str, Any]) -> bool:
        return _event_kind(event) == "network_pinning"

    return [
        _absence_test(
            "network",
            "MAK-DYN-0220",
            events,
            evidence,
            health,
            health_id,
            relevant=network,
            failing=cleartext,
            findings=findings,
            pass_text="No cleartext HTTP origin was observed among covered network activity exercised in this flow.",
            fail_text="A cleartext HTTP origin was directly observed at runtime.",
        ),
        _positive_inventory_test(
            "network",
            "MAK-DYN-0221",
            events,
            evidence,
            health_id,
            matching=validation,
            success_text="TLS trust/hostname validation API use was observed; this confirms instrumentation coverage, not correctness of custom validation.",
            missing_text="No covered TLS trust/hostname validation API was exercised, so validation behavior remains inconclusive.",
        ),
        _positive_inventory_test(
            "network",
            "MAK-DYN-0222",
            events,
            evidence,
            health_id,
            matching=pinning,
            success_text="Certificate-pinning invocation was observed and not bypassed.",
            missing_text="Pinning was not observed; absence is not treated as failure because applicability depends on the app's threat model and exercised stack.",
        ),
    ]


def _evaluate_authentication(
    events: list[dict[str, Any]],
    evidence: list[EvidenceRecord],
    health_id: str,
    findings: list[Finding],
) -> list[AtomicTestResult]:
    definition = _definition("authentication", "MAK-DYN-0230")
    biometric = [
        (event, record)
        for event, record in zip(events, evidence, strict=True)
        if _event_kind(event) == "biometric_authentication"
    ]
    ids = [health_id, *[record.evidence_id for _, record in biometric]]
    unbound = [event for event, _ in biometric if not bool(event.get("crypto_bound"))]
    if unbound:
        return [
            _result(
                definition,
                AssessmentStatus.INCONCLUSIVE,
                f"Observed {len(unbound)} biometric authentication call(s) without CryptoObject binding.",
                "Whether CryptoObject binding is required depends on the protected operation and threat model; runtime observation alone does not establish a vulnerability.",
                evidence_ids=ids,
                finding_ids=_failure_ids(findings, definition.test_id),
                severity=definition.default_severity,
            )
        ]
    if biometric:
        return [
            _result(
                definition,
                AssessmentStatus.PASS,
                f"Observed {len(biometric)} biometric authentication call(s) with CryptoObject binding.",
                "Observed biometric calls were cryptographically bound in the exercised flow; this scoped PASS does not establish complete authentication compliance.",
                evidence_ids=ids,
            )
        ]
    return [
        _result(
            definition,
            AssessmentStatus.INCONCLUSIVE,
            "No BiometricPrompt authentication call was observed in the exercised flow.",
            "The biometric binding test was not exercised.",
            evidence_ids=ids,
        )
    ]


def _evaluate_webview(
    events: list[dict[str, Any]],
    evidence: list[EvidenceRecord],
    health: HookHealth,
    health_id: str,
    findings: list[Finding],
) -> list[AtomicTestResult]:
    snapshots = [
        (event, record)
        for event, record in zip(events, evidence, strict=True)
        if _event_kind(event) == "webview_snapshot"
    ]
    risky = [
        (event, record)
        for event, record in snapshots
        if bool(event.get("allowFileAccess")) or bool(event.get("allowContentAccess"))
    ]
    definition_settings = _definition("webview", "MAK-DYN-0240")
    settings_ids = [health_id, *[record.evidence_id for _, record in snapshots]]
    if risky:
        settings_result = _result(
            definition_settings,
            AssessmentStatus.INCONCLUSIVE,
            f"Observed {len(risky)} WebView snapshot(s) with file/content access enabled.",
            "The setting can increase exposure, but content trust and reachable resources must be validated before a vulnerability conclusion.",
            evidence_ids=settings_ids,
            finding_ids=_failure_ids(findings, definition_settings.test_id),
            severity=definition_settings.default_severity,
        )
    elif snapshots:
        settings_result = _result(
            definition_settings,
            AssessmentStatus.PASS,
            f"Observed {len(snapshots)} WebView snapshot(s) with file/content access disabled.",
            "Observed WebView instances used restrictive local-resource settings in the exercised flow.",
            evidence_ids=settings_ids,
        )
    else:
        settings_result = _result(
            definition_settings,
            AssessmentStatus.INCONCLUSIVE,
            "No WebView configuration snapshot was observed.",
            "The WebView settings test was not exercised.",
            evidence_ids=settings_ids,
        )

    definition_debug = _definition("webview", "MAK-DYN-0241")
    debug_events = [
        (event, record)
        for event, record in zip(events, evidence, strict=True)
        if _event_kind(event) == "webview_debugging"
    ]
    debug_ids = [health_id, *[record.evidence_id for _, record in debug_events]]
    enabled = [event for event, _ in debug_events if bool(event.get("enabled"))]
    if enabled:
        debug_result = _result(
            definition_debug,
            AssessmentStatus.FAIL,
            f"Observed {len(enabled)} runtime call(s) enabling WebView debugging.",
            "WebView debugging was explicitly enabled at runtime.",
            evidence_ids=debug_ids,
            finding_ids=_failure_ids(findings, definition_debug.test_id),
            severity=definition_debug.default_severity,
        )
    elif debug_events:
        debug_result = _result(
            definition_debug,
            AssessmentStatus.PASS,
            "Observed runtime configuration explicitly disabling WebView debugging.",
            "WebView debugging was explicitly disabled in the exercised flow.",
            evidence_ids=debug_ids,
        )
    else:
        debug_result = _result(
            definition_debug,
            AssessmentStatus.INCONCLUSIVE,
            "No runtime WebView debugging configuration call was observed.",
            "The default/effective setting cannot be concluded from absence of a setter call alone.",
            evidence_ids=debug_ids,
        )

    definition_bridge = _definition("webview", "MAK-DYN-0242")
    bridges = [
        (event, record)
        for event, record in zip(events, evidence, strict=True)
        if _event_kind(event) == "webview_javascript_interface"
    ]
    bridge_ids = [health_id, *[record.evidence_id for _, record in bridges]]
    if bridges:
        bridge_result = _result(
            definition_bridge,
            AssessmentStatus.INCONCLUSIVE,
            f"Observed {len(bridges)} JavaScript interface registration(s).",
            "Sensitive functionality and reachability from untrusted content require code/content-origin validation before FAIL can be concluded.",
            evidence_ids=bridge_ids,
            finding_ids=_failure_ids(findings, definition_bridge.test_id),
            severity=definition_bridge.default_severity,
        )
    elif snapshots and _health_ready(health):
        bridge_result = _result(
            definition_bridge,
            AssessmentStatus.PASS,
            "WebView activity was observed with healthy hooks and no JavaScript interface registration during the exercised flow.",
            "No native bridge registration was observed in the scoped WebView activity.",
            evidence_ids=bridge_ids,
        )
    else:
        bridge_result = _result(
            definition_bridge,
            AssessmentStatus.INCONCLUSIVE,
            "No JavaScript interface registration was observed, but WebView/hook evidence was insufficient for scoped PASS.",
            "Absence of bridge events alone is not conclusive.",
            evidence_ids=bridge_ids,
        )
    return [settings_result, debug_result, bridge_result]


def _evaluate_privacy(
    events: list[dict[str, Any]],
    evidence: list[EvidenceRecord],
    health: HookHealth,
    health_id: str,
    findings: list[Finding],
) -> list[AtomicTestResult]:
    def privacy_activity(event: dict[str, Any]) -> bool:
        return _event_kind(event).startswith("privacy_")

    def clipboard(event: dict[str, Any]) -> bool:
        return _event_kind(event) == "privacy_clipboard_write"

    def logging(event: dict[str, Any]) -> bool:
        return _event_kind(event) == "privacy_log_call"

    def flag_secure(event: dict[str, Any]) -> bool:
        return _event_kind(event) == "privacy_flag_secure"

    def location(event: dict[str, Any]) -> bool:
        return _event_kind(event) == "privacy_location_request"

    definition_clipboard = _definition("privacy", "MAK-DYN-0250")
    clipboard_events = [event for event in events if clipboard(event)]
    clipboard_ids = [health_id, *_event_ids(events, evidence, clipboard)]
    if clipboard_events:
        clipboard_result = _result(
            definition_clipboard,
            AssessmentStatus.INCONCLUSIVE,
            f"Observed {len(clipboard_events)} clipboard write(s); contents were not captured.",
            "Clipboard use requires contextual review of whether sensitive data can be exposed; observation alone is not automatically a vulnerability.",
            evidence_ids=clipboard_ids,
            finding_ids=_failure_ids(findings, definition_clipboard.test_id),
            severity=definition_clipboard.default_severity,
        )
    elif _health_ready(health) and any(privacy_activity(event) for event in events):
        clipboard_result = _result(
            definition_clipboard,
            AssessmentStatus.PASS,
            "Privacy APIs were exercised with healthy hooks and no clipboard write was observed.",
            "No clipboard write was observed in the exercised flow; PASS is scoped to this flow.",
            evidence_ids=clipboard_ids,
        )
    else:
        clipboard_result = _result(
            definition_clipboard,
            AssessmentStatus.INCONCLUSIVE,
            "No clipboard write was observed, but hook/API activity was insufficient for scoped PASS.",
            "Absence alone is not conclusive.",
            evidence_ids=clipboard_ids,
        )

    logging_result = _positive_inventory_test(
        "privacy",
        "MAK-DYN-0251",
        events,
        evidence,
        health_id,
        matching=logging,
        success_text="Logging API calls were inventoried without collecting message content.",
        missing_text="Logging APIs were not observed in the exercised flow; no conclusion about logging behavior is made.",
    )
    secure_result = _positive_inventory_test(
        "privacy",
        "MAK-DYN-0252",
        events,
        evidence,
        health_id,
        matching=flag_secure,
        success_text="FLAG_SECURE use was observed; MobileAuditKit did not alter window flags.",
        missing_text="FLAG_SECURE was not observed; absence is not treated as failure because applicability is screen/context dependent.",
    )
    location_result = _positive_inventory_test(
        "privacy",
        "MAK-DYN-0253",
        events,
        evidence,
        health_id,
        matching=location,
        success_text="Location request APIs were inventoried without collecting coordinates.",
        missing_text="Location access APIs were not observed in the exercised flow.",
    )
    return [clipboard_result, logging_result, secure_result, location_result]


def _evaluate_resilience(
    events: list[dict[str, Any]],
    evidence: list[EvidenceRecord],
    health_id: str,
) -> list[AtomicTestResult]:
    def root_check(event: dict[str, Any]) -> bool:
        return _event_kind(event) == "resilience_root_check"

    def debug_check(event: dict[str, Any]) -> bool:
        return _event_kind(event) == "resilience_debug_check"

    return [
        _positive_inventory_test(
            "resilience",
            "MAK-DYN-0260",
            events,
            evidence,
            health_id,
            matching=root_check,
            success_text="Root-detection activity was observed and its result was not modified.",
            missing_text="Root-detection activity was not observed; absence is not treated as failure because applicability and exercised paths vary.",
        ),
        _positive_inventory_test(
            "resilience",
            "MAK-DYN-0261",
            events,
            evidence,
            health_id,
            matching=debug_check,
            success_text="Debugger-detection activity was observed and its result was not modified.",
            missing_text="Debugger-detection activity was not observed; absence is not treated as failure because applicability and exercised paths vary.",
        ),
    ]


def evaluate_runtime_module(
    module: str,
    events: list[dict[str, Any]],
    health: HookHealth,
    package: str | None,
) -> RuntimeAnalysisResult:
    """Evaluate one module's redacted events into atomic runtime test results."""
    event_evidence = [
        make_evidence(
            source=f"frida:{module}",
            module=module,
            test_id=None,
            evidence_type="runtime-event",
            data=event,
        )
        for event in events
    ]
    health_evidence = make_evidence(
        source=f"frida:{module}",
        module=module,
        test_id=None,
        evidence_type="hook-health",
        data=health.model_dump(mode="json"),
    )
    findings = findings_from_events(module, events, package)
    for event, record, finding in zip(events, event_evidence, findings, strict=True):
        finding.test_id = _finding_test_id(event)
        finding.evidence_ids = [record.evidence_id]
        finding.evidence = record.data

    if module == "crypto":
        tests = _evaluate_crypto(events, event_evidence, health, health_evidence.evidence_id, findings)
    elif module == "storage":
        tests = _evaluate_storage(events, event_evidence, health, health_evidence.evidence_id, findings)
    elif module == "network":
        tests = _evaluate_network(events, event_evidence, health, health_evidence.evidence_id, findings)
    elif module == "authentication":
        tests = _evaluate_authentication(events, event_evidence, health_evidence.evidence_id, findings)
    elif module == "webview":
        tests = _evaluate_webview(events, event_evidence, health, health_evidence.evidence_id, findings)
    elif module == "privacy":
        tests = _evaluate_privacy(events, event_evidence, health, health_evidence.evidence_id, findings)
    elif module == "resilience":
        tests = _evaluate_resilience(events, event_evidence, health_evidence.evidence_id)
    else:
        raise ValueError(f"Unsupported dynamic module: {module}")

    registered = {item.test_id for item in tests_for_module(module, engine="dynamic")}
    produced = {item.test_id for item in tests}
    if registered != produced:
        missing = sorted(registered - produced)
        extra = sorted(produced - registered)
        raise RuntimeError(
            f"Runtime evaluator/registry mismatch for {module}: missing={missing}, extra={extra}"
        )

    return RuntimeAnalysisResult(
        findings=findings,
        tests=tests,
        evidence=[*event_evidence, health_evidence],
        hook_health=health,
    )
