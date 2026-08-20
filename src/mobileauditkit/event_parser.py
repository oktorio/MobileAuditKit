from __future__ import annotations

import hashlib
import json
from typing import Any

from mobileauditkit.models import Confidence, Finding, Severity
from mobileauditkit.modules import get_module
from mobileauditkit.redaction import redact


def _base(module: str, event: dict[str, Any], package: str | None) -> dict[str, Any]:
    spec = get_module(module)
    stable = json.dumps(redact(event), sort_keys=True, default=str).encode()
    return {
        "finding_id": f"MAK-{module.upper()[:4]}-{hashlib.sha256(stable).hexdigest()[:8].upper()}",
        "module": module,
        "package": package,
        "confidence": Confidence.OBSERVED,
        "evidence": redact(event),
        "owasp_mobile_top10": list(spec.owasp),
        "masvs": list(spec.masvs),
        "mastg": list(spec.mastg),
        "maswe": list(spec.maswe),
    }


def _finding(base: dict[str, Any], **changes: Any) -> Finding:
    payload = dict(base)
    payload.update(changes)
    return Finding(**payload)


def finding_from_event(
    module: str, event: dict[str, Any], package: str | None = None
) -> Finding:
    kind = str(event.get("event", "runtime_observation"))
    base = _base(module, event, package)
    if kind == "crypto_algorithm":
        algorithm = str(event.get("algorithm", "unknown"))
        upper = algorithm.upper().strip()
        if upper in {"MD5", "SHA-1", "SHA1"}:
            return _finding(
                base,
                title=f"Weak hash algorithm observed: {algorithm}",
                description="A deprecated hash algorithm was invoked at runtime; review its security context.",
                severity=Severity.HIGH,
                maswe=["MASWE-0008"],
                cwe=["CWE-328"],
                remediation="Use a currently accepted hash or purpose-built KDF as appropriate.",
            )
        weak_symmetric = (
            upper == "AES"
            or (not upper.startswith("RSA/") and "/ECB" in upper)
            or upper.startswith("DES")
            or "3DES" in upper
        )
        if weak_symmetric:
            return _finding(
                base,
                title=f"Potentially weak encryption configuration observed: {algorithm}",
                description="A weak or pattern-leaking symmetric encryption configuration was invoked.",
                severity=Severity.HIGH,
                maswe=["MASWE-0007"],
                mastg=["MASTG-TEST-0232"],
                remediation="Use a modern authenticated-encryption construction where appropriate.",
            )
        return _finding(
            base,
            title=f"Cryptographic API observed: {algorithm}",
            description="Algorithm use observed without capturing keys or data.",
            severity=Severity.INFO,
        )
    if kind == "storage_external":
        return _finding(
            base,
            title="External/shared storage API observed",
            description="A shared/external storage location was referenced; no file content was captured.",
            severity=Severity.MEDIUM,
            maswe=["MASWE-0002"],
            mastg=["MASTG-TEST-0201"],
        )
    if kind in {"storage_shared_preferences", "storage_file", "storage_database"}:
        return _finding(
            base,
            title="Local storage API usage observed",
            description="Local storage use was observed without reading stored values or database content.",
            severity=Severity.INFO,
        )
    if kind == "network_cleartext":
        return _finding(
            base,
            title="Cleartext HTTP endpoint observed",
            description="An HTTP URL was constructed/requested; query strings and credentials are not collected.",
            severity=Severity.HIGH,
            maswe=["MASWE-0050"],
            mastg=["MASTG-TEST-0236"],
            cwe=["CWE-319"],
            remediation="Use HTTPS/TLS and disable unnecessary cleartext traffic.",
        )
    if kind == "network_pinning":
        return _finding(
            base,
            title="Certificate pinning control invoked",
            description="Pinning was observed and not bypassed or modified.",
            severity=Severity.INFO,
            masvs=["MASVS-NETWORK-2"],
        )
    if kind in {"network_tls_context", "network_hostname_verifier", "network_trust_manager"}:
        return _finding(
            base,
            title="TLS validation-related API observed",
            description="TLS/identity-validation API use was observed; this is not an insecurity conclusion.",
            severity=Severity.INFO,
        )
    if kind == "biometric_authentication":
        if not bool(event.get("crypto_bound")):
            return _finding(
                base,
                title="Biometric authentication invoked without CryptoObject",
                description="BiometricPrompt was invoked without cryptographic binding; assess whether the protected operation requires it.",
                severity=Severity.MEDIUM,
                maswe=["MASWE-0020"],
                mastg=["MASTG-TEST-0327"],
                remediation="For sensitive local operations, bind authentication to Android Keystore key use where required by the threat model.",
            )
        return _finding(
            base,
            title="Crypto-bound biometric authentication observed",
            description="BiometricPrompt used a CryptoObject; authentication was not altered.",
            severity=Severity.INFO,
            masvs=["MASVS-AUTH-2"],
        )
    if kind == "webview_snapshot":
        risky = bool(event.get("allowFileAccess")) or bool(event.get("allowContentAccess"))
        return _finding(
            base,
            title="WebView security configuration snapshot",
            description="Security-relevant WebView settings were observed before URL loading.",
            severity=Severity.MEDIUM if risky else Severity.INFO,
            remediation="Use restrictive WebView defaults and enable only required capabilities."
            if risky
            else None,
        )
    if kind == "webview_debugging":
        enabled = bool(event.get("enabled"))
        return _finding(
            base,
            title=f"WebView debugging {'enabled' if enabled else 'disabled'} at runtime",
            description="WebView debugging configuration was observed and not modified.",
            severity=Severity.MEDIUM if enabled else Severity.INFO,
            masvs=["MASVS-CODE-2", "MASVS-PLATFORM-2"],
            mastg=["MASTG-TEST-0227"],
        )
    if kind == "webview_javascript_interface":
        return _finding(
            base,
            title="WebView JavaScript interface registered",
            description="A Java object was exposed to WebView JavaScript; no method was invoked by MobileAuditKit.",
            severity=Severity.MEDIUM,
            mastg=["MASTG-TEST-0334"],
        )
    if kind == "privacy_clipboard_write":
        return _finding(
            base,
            title="Clipboard write observed",
            description="The app wrote to the system clipboard; clipboard contents were not captured.",
            severity=Severity.LOW,
            maswe=["MASWE-0030"],
        )
    if kind in {"privacy_log_call", "privacy_location_request", "privacy_flag_secure"}:
        return _finding(
            base,
            title="Privacy-relevant API observed",
            description="A privacy-relevant API was invoked without capturing user content.",
            severity=Severity.INFO,
        )
    if kind in {"resilience_root_check", "resilience_debug_check"}:
        return _finding(
            base,
            title="Runtime resilience control observed",
            description="A root/debugging detection mechanism ran; its result was not suppressed or modified.",
            severity=Severity.INFO,
        )
    if kind == "agent_error":
        return _finding(
            base,
            title="Observer runtime error",
            description="The Frida observer reported a runtime error; review device/API compatibility.",
            severity=Severity.INFO,
        )
    return _finding(
        base,
        title=f"Runtime observation: {kind}",
        description="A security-relevant runtime event was observed.",
        severity=Severity.INFO,
    )


def findings_from_events(
    module: str, events: list[dict[str, Any]], package: str | None = None
) -> list[Finding]:
    return [finding_from_event(module, event, package) for event in events]
