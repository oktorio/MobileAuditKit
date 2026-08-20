# Atomic Test Registry

The registry in `src/mobileauditkit/registry/tests.yaml` defines stable MobileAuditKit test IDs and framework mappings.

Each test follows the MASTG v2-inspired structure:

1. Defined scope and engine.
2. Raw observation.
3. Explicit evaluation rule.
4. PASS / FAIL / INCONCLUSIVE / NOT_TESTED status.
5. Evidence IDs and hashes.
6. Framework traceability.

A MobileAuditKit PASS means the local atomic test's failure condition was not met. It must not be represented as independent MASVS certification.
