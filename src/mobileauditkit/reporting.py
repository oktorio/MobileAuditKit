from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from mobileauditkit.models import AssessmentReport, Finding, Severity, StaticAnalysisResult
from mobileauditkit.redaction import redact

_ENV = Environment(autoescape=select_autoescape(default=True))

_FINDINGS_TEMPLATE = _ENV.from_string(
    """<!doctype html><html><head><meta charset='utf-8'><title>MobileAuditKit Report</title>
<style>body{font-family:system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem}.finding,.meta{border:1px solid #ddd;border-radius:10px;padding:1rem;margin:1rem 0}pre{overflow:auto;background:#f6f8fa;padding:.8rem}</style></head>
<body><h1>MobileAuditKit Security Assessment Report</h1><div class='meta'><pre>{{ metadata }}</pre></div><h2>Summary</h2><pre>{{ summary }}</pre><h2>Findings</h2>{% for f in findings %}<div class='finding'><h3>{{ f.finding_id }} — {{ f.title }}</h3><p><b>{{ f.severity }}</b> · {{ f.confidence }}{% if f.module %} · {{ f.module }}{% endif %}{% if f.test_id %} · {{ f.test_id }}{% endif %}</p><p>{{ f.description }}</p>{% if f.risk %}<p><b>Risk:</b> {{ f.risk }}</p>{% endif %}{% if f.remediation %}<p><b>Remediation:</b> {{ f.remediation }}</p>{% endif %}<p><b>OWASP:</b> {{ f.owasp_mobile_top10|join(', ') }}<br><b>MASVS:</b> {{ f.masvs|join(', ') }}<br><b>MASWE:</b> {{ f.maswe|join(', ') }}<br><b>MASTG:</b> {{ f.mastg|join(', ') }}</p><details><summary>Redacted evidence references</summary><pre>{{ f.evidence_json }}</pre></details></div>{% endfor %}</body></html>"""
)

_ASSESSMENT_TEMPLATE = _ENV.from_string(
    """<!doctype html><html><head><meta charset='utf-8'><title>MobileAuditKit Consolidated Assessment</title><style>body{font-family:system-ui;max-width:1220px;margin:2rem auto;padding:0 1rem;line-height:1.45}table{width:100%;border-collapse:collapse;margin:1rem 0}th,td{border:1px solid #ddd;padding:.55rem;text-align:left;vertical-align:top}.cards{display:flex;gap:.8rem;flex-wrap:wrap}.card,.finding,.notice{border:1px solid #ddd;border-radius:10px;padding:1rem;margin:.7rem 0}.card{min-width:130px}pre{overflow:auto;background:#f6f8fa;padding:.8rem}.PASS,.FAIL,.INCONCLUSIVE,.NOT_TESTED{font-weight:700}.muted{color:#666;font-size:.9em}</style></head><body><h1>MobileAuditKit Consolidated Assessment</h1><div class='notice'><b>Assessment ID:</b> {{ report.assessment_id }}<br><b>Profile:</b> {{ report.profile }} — {{ report.profile_description }}<br><b>Package:</b> {{ report.package or 'n/a' }} · <b>APK:</b> {{ report.apk or 'n/a' }}<br><b>APK SHA-256:</b> {{ report.metadata.apk_sha256 or 'n/a' }}<br><b>Tool version:</b> {{ report.tool_version }} · <b>Registry:</b> {{ report.metadata.registry_version or 'n/a' }}<br><b>Started:</b> {{ report.started_at }} · <b>Completed:</b> {{ report.completed_at }}</div><h2>Module coverage</h2><div class='cards'><div class='card'><b>PASS</b><br>{{ report.coverage.pass_count }}</div><div class='card'><b>FAIL</b><br>{{ report.coverage.fail_count }}</div><div class='card'><b>INCONCLUSIVE</b><br>{{ report.coverage.inconclusive_count }}</div><div class='card'><b>NOT TESTED</b><br>{{ report.coverage.not_tested_count }}</div><div class='card'><b>Execution coverage</b><br>{{ report.coverage.execution_coverage_percent }}%</div><div class='card'><b>Conclusive coverage</b><br>{{ report.coverage.conclusive_coverage_percent }}%</div></div><p class='muted'>{{ report.metadata.status_semantics }}</p><h2>Module evaluation</h2><table><thead><tr><th>Module</th><th>Engine</th><th>Status</th><th>Threshold</th><th>Atomic tests</th><th>Observation</th><th>Evaluation</th></tr></thead><tbody>{% for m in report.modules %}<tr><td>{{ m.module }}</td><td>{{ m.engine }}</td><td class='{{ m.status }}'>{{ m.status }}</td><td>{{ m.fail_threshold }}</td><td>{{ m.test_ids|join(', ') or '-' }}</td><td>{{ m.observation }}</td><td>{{ m.evaluation }}{% if m.error %}<br><small>Error: {{ m.error }}</small>{% endif %}</td></tr>{% endfor %}</tbody></table><h2>Atomic test matrix</h2><p class='muted'>Atomic-test status is test-specific. A PASS does not independently certify a MASVS control.</p><table><thead><tr><th>Test</th><th>Module</th><th>Status</th><th>Severity</th><th>MASVS</th><th>Observation</th><th>Evaluation</th><th>Evidence</th></tr></thead><tbody>{% for t in report.tests %}<tr><td>{{ t.test_id }}<br><small>{{ t.title }}</small></td><td>{{ t.module }}</td><td class='{{ t.status }}'>{{ t.status }}</td><td>{{ t.severity or '-' }}</td><td>{{ t.masvs|join(', ') or '-' }}</td><td>{{ t.observation }}</td><td>{{ t.evaluation }}</td><td>{{ t.evidence_ids|join(', ') or '-' }}</td></tr>{% endfor %}</tbody></table><h2>MASVS-linked test coverage</h2><p class='muted'>This matrix shows execution/conclusion of tests mapped to MASVS controls; it is not a compliance score.</p><table><thead><tr><th>MASVS control</th><th>Tests</th><th>PASS</th><th>FAIL</th><th>INCONCLUSIVE</th><th>NOT TESTED</th><th>Execution</th><th>Conclusive</th></tr></thead><tbody>{% for c in report.masvs_coverage %}<tr><td>{{ c.control_id }}</td><td>{{ c.total_tests }}</td><td>{{ c.pass_count }}</td><td>{{ c.fail_count }}</td><td>{{ c.inconclusive_count }}</td><td>{{ c.not_tested_count }}</td><td>{{ c.execution_coverage_percent }}%</td><td>{{ c.conclusive_coverage_percent }}%</td></tr>{% endfor %}</tbody></table><h2>Findings ({{ report.findings|length }})</h2>{% for f in report.findings %}<div class='finding'><h3>{{ f.finding_id }} — {{ f.title }}</h3><p><b>{{ f.severity }}</b> · {{ f.confidence }}{% if f.module %} · {{ f.module }}{% endif %}{% if f.test_id %} · {{ f.test_id }}{% endif %}</p><p>{{ f.description }}</p>{% if f.remediation %}<p><b>Remediation:</b> {{ f.remediation }}</p>{% endif %}<p><b>OWASP:</b> {{ f.owasp_mobile_top10|join(', ') }}<br><b>MASVS:</b> {{ f.masvs|join(', ') }}<br><b>MASWE:</b> {{ f.maswe|join(', ') }}<br><b>MASTG:</b> {{ f.mastg|join(', ') }}</p><p><b>Evidence:</b> {{ f.evidence_ids|join(', ') or '-' }}</p></div>{% else %}<p>No finding records were generated.</p>{% endfor %}<h2>Evidence appendix ({{ report.evidence|length }})</h2><table><thead><tr><th>Evidence ID</th><th>Source</th><th>Type</th><th>Test</th><th>SHA-256</th><th>Redacted data</th></tr></thead><tbody>{% for e in report.evidence %}<tr><td>{{ e.evidence_id }}</td><td>{{ e.source }}</td><td>{{ e.evidence_type }}</td><td>{{ e.test_id or '-' }}</td><td><code>{{ e.sha256 }}</code></td><td><pre>{{ e.data_json }}</pre></td></tr>{% endfor %}</tbody></table></body></html>"""
)

_STATIC_TEMPLATE = _ENV.from_string(
    """<!doctype html><html><head><meta charset='utf-8'><title>MobileAuditKit Static Analysis</title><style>body{font-family:system-ui;max-width:1180px;margin:2rem auto;padding:0 1rem}table{width:100%;border-collapse:collapse}th,td{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top}pre{white-space:pre-wrap}.PASS,.FAIL,.INCONCLUSIVE,.NOT_TESTED{font-weight:700}</style></head><body><h1>MobileAuditKit Static APK Analysis</h1><pre>{{ metadata }}</pre><h2>Atomic tests</h2><table><tr><th>Test</th><th>Status</th><th>Observation</th><th>Evaluation</th><th>Evidence</th></tr>{% for t in result.tests %}<tr><td>{{ t.test_id }} — {{ t.title }}</td><td class='{{ t.status }}'>{{ t.status }}</td><td>{{ t.observation }}</td><td>{{ t.evaluation }}</td><td>{{ t.evidence_ids|join(', ') }}</td></tr>{% endfor %}</table><h2>Findings</h2>{% for f in result.findings %}<h3>{{ f.finding_id }} — {{ f.title }}</h3><p>{{ f.description }}</p>{% if f.remediation %}<p><b>Remediation:</b> {{ f.remediation }}</p>{% endif %}{% else %}<p>No finding records were generated.</p>{% endfor %}</body></html>"""
)


def _payload(findings: Iterable[Finding], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    items = [redact(f.model_dump(mode="json")) for f in findings]
    return {"tool": "MobileAuditKit", "metadata": redact(metadata or {}), "summary": dict(Counter(i["severity"] for i in items)), "findings": items}


def write_json_report(findings: Iterable[Finding], path: Path, metadata: dict[str, Any] | None = None) -> Path:
    payload = _payload(findings, metadata)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def write_html_report(findings: Iterable[Finding], path: Path, metadata: dict[str, Any] | None = None) -> Path:
    payload = _payload(findings, metadata)
    decorated = []
    for item in payload["findings"]:
        current = dict(item)
        current["evidence_json"] = json.dumps(current.get("evidence", {}), indent=2, sort_keys=True)
        decorated.append(current)
    html = _FINDINGS_TEMPLATE.render(metadata=json.dumps(payload["metadata"], indent=2), summary=json.dumps(payload["summary"], indent=2), findings=decorated)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path


def _assessment_payload(report: AssessmentReport) -> dict[str, Any]:
    return redact(report.model_dump(mode="json"))


def write_assessment_json(report: AssessmentReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_assessment_payload(report), indent=2, sort_keys=True), encoding="utf-8")
    return path


def write_assessment_html(report: AssessmentReport, path: Path) -> Path:
    payload = _assessment_payload(report)
    for item in payload["evidence"]:
        item["data_json"] = json.dumps(item.get("data", {}), indent=2, sort_keys=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_ASSESSMENT_TEMPLATE.render(report=payload), encoding="utf-8")
    return path


def write_static_analysis_json(result: StaticAnalysisResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = redact(result.model_dump(mode="json"))
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def write_static_analysis_html(result: StaticAnalysisResult, path: Path) -> Path:
    payload = redact(result.model_dump(mode="json"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_STATIC_TEMPLATE.render(result=payload, metadata=json.dumps(payload["metadata"], indent=2)), encoding="utf-8")
    return path


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _sarif_rule(finding: Finding) -> dict[str, Any]:
    rule_id = finding.test_id or finding.finding_id
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {"text": finding.remediation or "Review the MobileAuditKit finding and supporting evidence."},
        "properties": {
            "tags": [*finding.owasp_mobile_top10, *finding.masvs, *finding.maswe, *finding.mastg, *finding.cwe],
            "security-severity": str({Severity.CRITICAL: 9.5, Severity.HIGH: 8.0, Severity.MEDIUM: 5.5, Severity.LOW: 3.0, Severity.INFO: 0.0}[finding.severity]),
        },
    }


def _sarif_result(finding: Finding, rule_index: int, default_location: str) -> dict[str, Any]:
    rule_id = finding.test_id or finding.finding_id
    fingerprint = hashlib.sha256(f"{rule_id}|{finding.finding_id}|{default_location}".encode()).hexdigest()
    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _sarif_level(finding.severity),
        "message": {"text": f"{finding.title}. {finding.description}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": default_location}}}],
        "partialFingerprints": {"primaryLocationLineHash": fingerprint},
        "properties": {"finding_id": finding.finding_id, "confidence": finding.confidence, "evidence_ids": finding.evidence_ids, "masvs": finding.masvs, "maswe": finding.maswe, "mastg": finding.mastg},
    }


def assessment_to_sarif(report: AssessmentReport, *, default_location: str = "AndroidManifest.xml") -> dict[str, Any]:
    findings = [finding for finding in report.findings if finding.severity != Severity.INFO]
    rules: list[dict[str, Any]] = []
    indexes: dict[str, int] = {}
    for finding in findings:
        rule_id = finding.test_id or finding.finding_id
        if rule_id not in indexes:
            indexes[rule_id] = len(rules)
            rules.append(_sarif_rule(finding))
    results = [_sarif_result(finding, indexes[finding.test_id or finding.finding_id], default_location) for finding in findings]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "MobileAuditKit", "version": report.tool_version, "informationUri": "https://github.com/oktorio/MobileAuditKit", "rules": rules}}, "automationDetails": {"id": report.assessment_id}, "results": results, "properties": {"profile": report.profile, "apk_sha256": report.metadata.get("apk_sha256"), "registry_version": report.metadata.get("registry_version")}}],
    }


def write_assessment_sarif(report: AssessmentReport, path: Path, *, default_location: str = "AndroidManifest.xml") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(assessment_to_sarif(report, default_location=default_location), indent=2, sort_keys=True), encoding="utf-8")
    return path
