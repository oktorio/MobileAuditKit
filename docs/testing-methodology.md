# Testing Methodology

MobileAuditKit separates **observation**, **contextual indication**, and **conclusive atomic evaluation**.

1. Define written authorization and scope.
2. Prefer a dedicated emulator/test device and synthetic accounts/data.
3. Record tool/device/app versions through the runtime fingerprint.
4. Inspect the APK before or alongside runtime testing when the artifact is available.
5. Select one meaningful flow label (for example `login`) and run the dynamic profile.
6. Exercise the relevant application journey throughout the shared observation window.
7. Review hook health before interpreting negative runtime observations.
8. Treat contextual observations as INCONCLUSIVE until required code/business context is validated.
9. Correlate authentication/authorization observations with backend behavior when applicable.
10. Persist only redacted/hash-addressed evidence and reports.

All enabled dynamic observers share one Frida session in v0.5. Runtime hooks call the original implementation and do not alter authentication, TLS validation, certificate pinning, root checks, debugger checks, application data, or transaction state.
