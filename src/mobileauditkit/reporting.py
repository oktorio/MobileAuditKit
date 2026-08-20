from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from mobileauditkit.models import AssessmentReport, Finding
from mobileauditkit.redaction import redact

_ENV = Environment(autoescape=select_autoescape(default=True))

_FINDINGS_TEMPLATE = _ENV.from_string("""<!doctype html><html><head><meta charset='utf-8'><title>MobileAuditKit Report</title><style>body{font-family:system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem}.finding,.meta{border:1px solid #ddd;border-radius:10px;padding:1rem;margin:1rem 0}pre{overflow:auto;background:#f6f8fa;padding:.8rem}</style></head><body><h1>MobileAuditKit Security Assessment Report</h1><div class='meta'><pre>{{ metadata }}</pre></div><h2>Summary</h2><pre>{{ summary }}</pre><h2>Findings</h2>{% for f in findings %}<div class='finding'><h3>{{ f.finding_id }} — {{ f.title }}</h3><p><b>{{ f.severity }}</b> · {{ f.confidence }}{% if f.module %} · {{ f.module }}{% endif %}</p><p>{{ f.description }}</p>{% if f.risk %}<p><b>Risk:</b> {{ f.risk }}</p>{% endif %}{% if f.remediation %}<p><b>Remediation:</b> {{ f.remediation }}</p>{% endif %}<p><b>OWASP:</b> {{ f.owasp_mobile_top10|join(', ') }}<br><b>MASVS:</b> {{ f.masvs|join(', ') }}<br><b>MASWE:</b> {{ f.maswe|join(', ') }}<br><b>MASTG:</b> {{ f.mastg|join(', ') }}</p><details><summary>Redacted evidence</summary><pre>{{ f.evidence_json }}</pre></details></div>{% endfor %}</body></html>""")

_ASSESSMENT_TEMPLATE = _ENV.from_string("""<!doctype html><html><head><meta charset='utf-8'><title>MobileAuditKit Consolidated Assessment</title><style>body{font-family:system-ui;max-width:1180px;margin:2rem auto;padding:0 1rem;line-height:1.45}table{width:100%;border-collapse:collapse;margin:1rem 0}th,td{border:1px solid #ddd;padding:.55rem;text-align:left;vertical-align:top}.cards{display:flex;gap:.8rem;flex-wrap:wrap}.card,.finding,.notice{border:1px solid #ddd;border-radius:10px;padding:1rem;margin:.7rem 0}.card{min-width:130px}pre{overflow:auto;background:#f6f8fa;padding:.8rem}.PASS,.FAIL,.INCONCLUSIVE,.NOT_TESTED{font-weight:700}</style></head><body><h1>MobileAuditKit Consolidated Assessment</h1><div class='notice'><b>Assessment ID:</b> {{ report.assessment_id }}<br><b>Profile:</b> {{ report.profile }} — {{ report.profile_description }}<br><b>Package:</b> {{ report.package or 'n/a' }} · <b>APK:</b> {{ report.apk or 'n/a' }}<br><b>Tool version:</b> {{ report.tool_version }}<br><b>Started:</b> {{ report.started_at }} · <b>Completed:</b> {{ report.completed_at }}</div><h2>Coverage</h2><div class='cards'><div class='card'><b>PASS</b><br>{{ report.coverage.pass_count }}</div><div class='card'><b>FAIL</b><br>{{ report.coverage.fail_count }}</div><div class='card'><b>INCONCLUSIVE</b><br>{{ report.coverage.inconclusive_count }}</div><div class='card'><b>NOT TESTED</b><br>{{ report.coverage.not_tested_count }}</div><div class='card'><b>Execution coverage</b><br>{{ report.coverage.execution_coverage_percent }}%</div><div class='card'><b>Conclusive coverage</b><br>{{ report.coverage.conclusive_coverage_percent }}%</div></div><p><small>{{ report.metadata.status_semantics }}</small></p><h2>Module evaluation</h2><table><thead><tr><th>Module</th><th>Engine</th><th>Status</th><th>Threshold</th><th>Observation</th><th>Evaluation</th></tr></thead><tbody>{% for m in report.modules %}<tr><td>{{ m.module }}</td><td>{{ m.engine }}</td><td class='{{ m.status }}'>{{ m.status }}</td><td>{{ m.fail_threshold }}</td><td>{{ m.observation }}</td><td>{{ m.evaluation }}{% if m.error %}<br><small>Error: {{ m.error }}</small>{% endif %}</td></tr>{% endfor %}</tbody></table><h2>Findings ({{ report.findings|length }})</h2>{% for f in report.findings %}<div class='finding'><h3>{{ f.finding_id }} — {{ f.title }}</h3><p><b>{{ f.severity }}</b> · {{ f.confidence }}{% if f.module %} · {{ f.module }}{% endif %}</p><p>{{ f.description }}</p>{% if f.remediation %}<p><b>Remediation:</b> {{ f.remediation }}</p>{% endif %}<p><b>OWASP:</b> {{ f.owasp_mobile_top10|join(', ') }}<br><b>MASVS:</b> {{ f.masvs|join(', ') }}<br><b>MASWE:</b> {{ f.maswe|join(', ') }}<br><b>MASTG:</b> {{ f.mastg|join(', ') }}</p><details><summary>Redacted evidence</summary><pre>{{ f.evidence_json }}</pre></details></div>{% else %}<p>No finding records were generated.</p>{% endfor %}</body></html>""")


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
    decorated_findings = []
    for item in payload["findings"]:
        current = dict(item)
        current["evidence_json"] = json.dumps(current.get("evidence", {}), indent=2, sort_keys=True)
        decorated_findings.append(current)
    payload["findings"] = decorated_findings
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_ASSESSMENT_TEMPLATE.render(report=payload), encoding="utf-8")
    return path
