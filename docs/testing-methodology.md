# Testing Methodology

MobileAuditKit separates **observation**, **indication**, and **confirmed configuration findings**.

1. Define written authorization and scope.
2. Prefer a dedicated emulator/test device and synthetic accounts/data.
3. Record tool and device versions with `mobileauditkit doctor`.
4. Inspect the APK manifest before runtime testing.
5. Run one observer at a time and exercise relevant application flows.
6. Review INFO/LOW observations manually before treating them as vulnerabilities.
7. Correlate authentication/authorization observations with backend behavior when applicable.
8. Persist only redacted evidence and reports.

Runtime modules are intentionally passive: hooks call the original implementation and do not alter authentication, TLS validation, root checks, debugger checks, application data, or transaction state.
