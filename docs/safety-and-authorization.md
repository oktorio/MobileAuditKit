# Safety and Authorization

MobileAuditKit is designed for defensive mobile application security assessment in environments where the tester owns the target or has explicit authorization to test it.

## Allowed project scope

The project may inspect configuration, instrument runtime APIs, observe security-control behavior, and generate redacted evidence required for assurance activities.

Examples include observing cryptographic algorithm selection, storage API usage, TLS/security configuration, biometric API invocation, WebView settings, exported-component configuration, and the presence or activation of root/integrity/anti-debug controls.

## Out of scope

Do not use or extend this project to:

- capture real passwords, PINs, OTPs, access tokens, session cookies, private keys, cardholder data, or customer records;
- bypass authentication, MFA, biometrics, authorization, or transaction controls;
- perform generic certificate-pinning bypasses;
- defeat root, tamper, integrity, anti-debug, or anti-instrumentation controls for unauthorized access;
- manipulate balances, beneficiaries, payment instructions, or financial transactions;
- establish persistence, deploy malware, evade defensive monitoring, or exfiltrate data.

## Evidence handling

Collect the minimum evidence necessary. Sensitive values must be redacted before console output, report generation, or persistence. Prefer metadata such as API, class, method, algorithm, control state, timestamp, and package/version context rather than raw values.

## Interpretation

A runtime observation is not necessarily a vulnerability. Findings should distinguish observed indicators from likely weaknesses and confirmed vulnerabilities, and should include enough context for manual validation.

## Lab recommendation

Develop and demonstrate new modules against intentionally vulnerable applications, emulators, or applications created specifically for testing. Do not commit commercial APKs or proprietary application material to this repository.
