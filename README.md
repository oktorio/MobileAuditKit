# MobileAuditKit

MobileAuditKit is a defensive, OWASP-aligned mobile application security assessment toolkit for **authorized Android testing**. It combines safe Frida runtime observation, APK configuration inspection, profile-driven assessment orchestration, and redacted JSON/HTML reporting.

> Use MobileAuditKit only on applications and devices you own or have explicit permission to assess.

## v0.3.0 — Assessment Engine

v0.3.0 adds a profile-driven assessment layer over the v0.2 observer modules.

### Assessment status model

Each enabled profile module receives one of four statuses:

- **PASS** — the module executed with sufficient evidence and no finding reached the profile's configured fail threshold within the exercised scope.
- **FAIL** — at least one finding met or exceeded the profile's configured fail threshold.
- **INCONCLUSIVE** — the module was attempted but failed, disconnected, or produced insufficient evidence for PASS/FAIL.
- **NOT_TESTED** — the module could not be executed because a required input was not supplied, such as an APK for static inspection or a package name for runtime observation.

`PASS` is deliberately scoped. It does **not** certify MASVS compliance and does not prove the absence of vulnerabilities outside the application paths exercised during the assessment.

### Built-in profiles

- **baseline** — APK configuration plus all safe runtime observers.
- **runtime** — dynamic Frida observers only.
- **static** — APK configuration inspection only.

Profiles are packaged with the Python distribution under `src/mobileauditkit/profiles/`. A custom YAML profile path can also be supplied to the assessment engine.

## Assessment modules

- **crypto** — observes algorithm/mode selection; never captures keys, IVs, plaintext, or ciphertext.
- **storage** — observes SharedPreferences, file, database, and external-storage APIs; never dumps values or databases.
- **network** — observes cleartext HTTP construction, TLS setup, hostname-verifier configuration, and certificate-pinning invocation; never disables TLS validation or pinning.
- **authentication** — observes platform/Jetpack `BiometricPrompt` and whether a `CryptoObject` is present; never bypasses authentication.
- **webview** — snapshots security-relevant WebView settings, JavaScript bridges, and debugging configuration; does not inject content.
- **privacy** — observes clipboard/log/location/screenshot-protection APIs without capturing clipboard content, log messages, or coordinates.
- **resilience** — observes root/debug detection checks without suppressing or changing their results.
- **apk-config** — parses the final AndroidManifest with Android SDK `apkanalyzer` and checks debuggable, backup, cleartext, and exported-component configuration.

## Safety boundary

MobileAuditKit does **not** implement universal SSL-pinning bypass, biometric bypass, root-detection bypass, credential interception, session hijacking, transaction manipulation, malware/persistence, or customer-data extraction. Runtime hooks call the original API implementation and reports are redacted before persistence.

## Install

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
mobileauditkit doctor
```

Runtime testing requires ADB plus compatible Frida client/server versions on an authorized device or emulator. APK inspection requires `apkanalyzer` from the Android SDK on `PATH`.

## v0.3 usage

List profiles:

```bash
mobileauditkit profiles
```

Run the combined baseline profile:

```bash
mobileauditkit scan \
  --package com.example.testapp \
  --apk sample.apk \
  --profile baseline \
  --seconds 20
```

Run only runtime observers:

```bash
mobileauditkit scan \
  --package com.example.testapp \
  --profile runtime \
  --seconds 20
```

Run static configuration inspection only:

```bash
mobileauditkit scan \
  --apk sample.apk \
  --profile static
```

By default, `scan` writes:

```text
reports/assessment.json
reports/assessment.html
```

You can override them with `--json-report` and `--html-report`.

Single-module v0.2 commands remain available:

```bash
mobileauditkit modules
mobileauditkit mappings masvs

mobileauditkit run \
  --package com.example.testapp \
  --module network \
  --seconds 20 \
  --json-report reports/network.json \
  --html-report reports/network.html

mobileauditkit inspect-apk sample.apk \
  --json-report reports/apk.json \
  --html-report reports/apk.html
```

## Consolidated assessment output

The v0.3 assessment report contains:

- assessment ID and tool version
- selected profile
- package/APK context
- per-module execution engine
- per-module PASS / FAIL / INCONCLUSIVE / NOT_TESTED status
- configured fail threshold
- observation and evaluation text
- event and finding counts
- highest severity observed
- execution coverage percentage
- conclusive coverage percentage
- deduplicated findings and OWASP mappings
- redacted evidence

The engine isolates module failures, so one incompatible observer does not discard results from other modules.

## Architecture

```mermaid
flowchart LR
    A[Authorized APK / App] --> P[Assessment Profile]
    P --> S[Static APK Checks]
    P --> F[Frida Runtime Observers]
    S --> E[Finding & Evidence Model]
    F --> R[Redaction]
    R --> E
    E --> V[Assessment Engine]
    V --> X[PASS / FAIL / INCONCLUSIVE / NOT_TESTED]
    X --> C[Coverage Summary]
    C --> J[Consolidated JSON]
    C --> H[Consolidated HTML]
```

## OWASP alignment

The project uses **OWASP Mobile Top 10 2024** as a risk taxonomy and **MASVS / MASWE / MASTG** as more granular control/testing references. Mapping files are packaged under `src/mobileauditkit/mappings/` with status dates because OWASP MAS is a living project. A mapping is evidence support, not automatic compliance certification.

## Limitations

- Dynamic coverage depends on application paths exercised during the observation window.
- An observed API call is not automatically a vulnerability.
- A module-level PASS only means no finding met that profile's fail threshold in the exercised scope.
- Absence of an observed security/resilience API does not prove the control is absent.
- Manifest inspection does not replace source review, backend authorization testing, network testing, or a complete MASVS assessment.
- Sequential runtime modules may require the tester to repeat relevant user journeys for each observation window.
- MASTG/MASWE identifiers and statuses should be revalidated when mappings are updated.

## Development

```bash
pip install -e '.[dev]'
pytest
ruff check .
```

## License

Apache-2.0. OWASP names and identifiers remain the property of their respective project/Foundation; consult OWASP licensing for reuse of OWASP content.
