# Assessment accuracy and runtime reliability

MobileAuditKit separates **security observations** from **instrumentation health**.

A negative-observation runtime PASS requires healthy instrumentation for the exercised flow. Agent errors, partial hook coverage, dropped events, interruption, failed script loading, or other incomplete instrumentation cannot support a PASS. A directly observed failing condition remains FAIL even if unrelated instrumentation later degrades.

## Android effective configuration

Static analysis evaluates effective Android behavior rather than only literal attribute presence. In particular, `usesCleartextTraffic` defaults to permitted for target SDK 27 and lower and denied for target SDK 28 and higher, unless Network Security Configuration changes the effective policy. Unresolved resource values remain distinct from absent attributes.

Backup XML is parsed structurally. Narrow or unrelated exclusions do not prove sensitive data protection and therefore remain INCONCLUSIVE.

Packaged HTTP strings are contextual indicators, not proof of observed network transmission. Android XML namespace declarations are ignored, matched endpoint values are discarded, and scan limits/skips/truncation are retained as metadata.

## CLI exit policies

The default scan behavior remains report-oriented and does not fail solely because findings or incomplete modules exist.

Use:

- `--exit-on-findings` to exit with code **2** when a module reaches FAIL.
- `--exit-on-incomplete` to exit with code **3** when a module is INCONCLUSIVE or NOT_TESTED.

Reports are written before these policy exits. Required inputs are validated against the selected profile; for example, the packaged `static` profile requires `--apk`.

## Validation boundary

Runtime observation remains defensive: hooks observe and call original implementations. MobileAuditKit does not add authentication, biometric, TLS/pinning, root/tamper bypass, credential extraction, session hijacking, or customer-data collection.
