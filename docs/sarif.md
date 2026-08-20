# SARIF Output

MobileAuditKit emits SARIF 2.1.0 for non-INFO findings.

Use a repository-relative `--sarif-location` when integrating with GitHub code scanning because GitHub requires at least one result location to display an alert.

```bash
mobileauditkit scan \
  --apk app-release.apk \
  --profile static \
  --sarif-report reports/mobileauditkit.sarif \
  --sarif-location app/src/main/AndroidManifest.xml
```

SARIF results include MobileAuditKit atomic test IDs as rule IDs, severity, stable partial fingerprints, evidence IDs, confidence, and OWASP mappings.
