# MobileAuditKit

**OWASP-aligned mobile application security assessment toolkit with Frida-based dynamic instrumentation.**

> **Authorized testing only.** Assess only applications and systems you own or have explicit permission to test.

MobileAuditKit is a defensive, evidence-oriented toolkit for Android application security reviews. It combines safe Frida runtime observation with lightweight APK/configuration inspection and maps findings to OWASP Mobile Top 10, MASVS, MASTG/MASWE and CWE where appropriate.

## Design goals

- Evidence-first mobile application security auditing
- Small, reusable Frida observer modules
- No credential interception, transaction manipulation, authentication bypass, universal TLS-pinning bypass, anti-Frida bypass, or persistence
- Sensitive-data redaction before console/file output
- Structured findings with confidence and severity
- General-purpose profiles, including optional high-assurance profiles later
- Offline-first; no telemetry and no external data upload

## Initial coverage

| Area | Runtime / Static approach |
|---|---|
| Cryptography | Observe algorithm/mode use; flag legacy primitives and ECB |
| Storage | Observe SharedPreferences/file/database APIs without dumping data |
| Network | Observe HTTP/TLS configuration and TrustManager/HostnameVerifier activity |
| Authentication | Observe BiometricPrompt/KeyStore authentication APIs; no bypass |
| WebView | Observe security-relevant WebView settings and interfaces |
| Privacy | Observe clipboard/logging and sensitive API use with redaction |
| Resilience | Detect presence/activation of root, integrity, anti-debug and instrumentation controls; do not defeat them |
| APK configuration | Planned static inspection for exported components, backup/debug/cleartext settings |

## OWASP alignment

The project is structured around the OWASP Mobile Top 10 and MASVS control groups:

- MASVS-STORAGE
- MASVS-CRYPTO
- MASVS-AUTH
- MASVS-NETWORK
- MASVS-PLATFORM
- MASVS-CODE
- MASVS-RESILIENCE
- MASVS-PRIVACY

Mappings live in `mappings/` and are kept separate from code so they can be maintained as standards evolve.

## Repository layout

```text
MobileAuditKit/
├── .github/workflows/
├── docs/
├── mappings/
├── profiles/
├── scripts/
│   ├── common/
│   ├── m03_authentication/
│   ├── m05_communication/
│   ├── m09_storage/
│   └── m10_cryptography/
├── src/mobileauditkit/
├── tests/
├── README.md
└── pyproject.toml
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .[dev]
```

For runtime Android testing, install a Frida client compatible with the Frida server used on the authorized test device/emulator.

## CLI

```bash
mobileauditkit --help
mobileauditkit doctor
mobileauditkit modules
mobileauditkit redact "Bearer eyJ..."
```

Planned assessment interface:

```bash
mobileauditkit run --package com.example.app --module crypto
mobileauditkit run --package com.example.app --module storage
mobileauditkit scan --package com.example.app --profile baseline
```

## Evidence model

Findings contain, where available:

- finding ID and title
- severity and confidence
- package/app/device context
- observed class/method
- redacted evidence
- OWASP Mobile Top 10 mapping
- MASVS / MASWE / MASTG mapping
- CWE mapping
- risk explanation and remediation

An observation is not automatically a vulnerability. Reports should distinguish **Observed**, **Likely**, and **Confirmed** evidence levels.

## Safety boundary

MobileAuditKit must not be used to capture real credentials, OTPs, PINs, session tokens, private cryptographic keys, customer data, or financial transaction data. Runtime values pass through a redaction layer before presentation or persistence.

The project intentionally does **not** provide generic mechanisms to bypass authentication, biometrics, certificate pinning, root detection, anti-tamper, or anti-instrumentation protections. It can observe these controls to support authorized assurance testing.

See [`docs/safety-and-authorization.md`](docs/safety-and-authorization.md).

## Roadmap

- [x] Project architecture and safety model
- [x] Structured finding model and redaction foundation
- [x] Initial crypto observer
- [ ] Frida device/session orchestration
- [ ] Storage/network/authentication/WebView observers
- [ ] APK manifest/configuration inspection
- [ ] HTML/JSON/SARIF reporting
- [ ] Expanded MASVS/MASTG/MASWE mappings
- [ ] SBOM and dependency inventory
- [ ] iOS assessment support
- [ ] Optional MobSF/JADX/apktool integrations

## Contributing

Contributions must preserve the defensive scope. Pull requests adding credential theft, unauthorized access, persistence, destructive behavior, transaction manipulation, or generic security-control bypasses will not be accepted.

## License

Apache-2.0. See `LICENSE`.
