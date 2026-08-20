# Atomic Test Registry

The registry in `src/mobileauditkit/registry/tests.yaml` defines stable MobileAuditKit test IDs and framework mappings.

Each test follows a MASTG v2-inspired structure:

1. Defined scope and engine.
2. Raw observation.
3. Explicit evaluation rule.
4. PASS / FAIL / INCONCLUSIVE / NOT_TESTED status.
5. Evidence IDs and hashes.
6. Framework traceability.

v0.5 decomposes the former module-level runtime summaries into focused `MAK-DYN-02xx` atomic tests. Dynamic PASS is scoped to the named flow and, for absence-based evaluations, requires both healthy observer coverage and relevant API activity. Context-dependent observations remain INCONCLUSIVE rather than being upgraded to FAIL from severity alone.

A MobileAuditKit PASS must not be represented as independent MASVS certification.
