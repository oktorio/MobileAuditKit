# Runtime Orchestration

MobileAuditKit v0.5 uses one Frida session for all enabled dynamic modules in an assessment profile.

## Lifecycle

1. Validate the authorized package and enabled dynamic modules.
2. Collect bounded device/app fingerprint metadata.
3. Attach once, or spawn once when `--spawn` is requested.
4. Load every enabled read-only observer script into the same session.
5. Resume the spawned process only after scripts are loaded.
6. Record a flow-start marker.
7. Exercise the named user journey for the configured observation window.
8. Record a flow-end marker.
9. Detach the session once.
10. Evaluate each module's events with its hook-health telemetry.

## Hook health

Agents emit a dedicated `hook_health` message after attempting their configured hook groups. Health messages are orchestration telemetry and are not converted into security findings.

A runtime test that relies on a negative observation may return PASS only when the observer reported healthy coverage and the relevant API family was actually exercised. Otherwise the result remains INCONCLUSIVE.

## Flow context

Use `--flow` to describe the exercised journey. The label is attached to runtime events and start/end markers. A single v0.5 scan represents one flow; run separate scans for materially different journeys when independent evidence is required.

## Fingerprinting and privacy

Fingerprinting is intentionally bounded to environment metadata required for reproducibility. The ADB serial is hashed before persistence. MobileAuditKit does not collect account data, credentials, tokens, clipboard contents, location coordinates, plaintext, keys, or transaction data.

## Failure semantics

- A directly observed failing condition can produce FAIL.
- Missing/partial hook health cannot turn a direct failure into PASS.
- Silence with degraded/unknown hooks is INCONCLUSIVE.
- Context-dependent controls remain INCONCLUSIVE until the required application context is established.
- Observer/session errors are INCONCLUSIVE rather than PASS.
