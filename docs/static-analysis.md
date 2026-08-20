# Deep APK Static Analysis

MobileAuditKit v0.4 treats the final APK as the primary static artifact. The engine uses `apkanalyzer` for final manifest/resource/DEX metadata and Python ZIP inspection for bounded package-content inventory.

## Evidence principles

- Hash the APK with SHA-256 before reporting results.
- Persist configuration facts and indicator counts, not extracted credentials or secret values.
- Keep code-context-dependent questions `INCONCLUSIVE` until supporting code/authorization review is available.
- Treat namespace/native-library inventories as supply-chain inputs, not vulnerability conclusions.

## Network Security Configuration

When `android:networkSecurityConfig` references `@xml/...`, MobileAuditKit asks `apkanalyzer resources xml` for the final packaged XML and evaluates production cleartext enablement and user-added CA trust anchors. Debug-only trust overrides are excluded from production trust findings.

## Package text scan bounds

Only selected text-like APK entries are scanned, with per-file and total-byte limits. Secret-format matches and `http://` values are discarded immediately; evidence stores only type/count and internal file path.
