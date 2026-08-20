from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from mobileauditkit.models import Finding
from mobileauditkit.redaction import redact

_TEMPLATE = Environment(autoescape=select_autoescape(default=True)).from_string("""<!doctype html><html><head><meta charset='utf-8'><title>MobileAuditKit Report</title><style>body{font-family:system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem}.finding,.meta{border:1px solid #ddd;border-radius:10px;padding:1rem;margin:1rem 0}pre{overflow:auto;background:#f6f8fa;padding:.8rem}</style></head><body><h1>MobileAuditKit Security Assessment Report</h1><div class='meta'><pre>{{ metadata }}</pre></div><h2>Summary</h2><pre>{{ summary }}</pre><h2>Findings</h2>{% for f in findings %}<div class='finding'><h3>{{ f.finding_id }} — {{ f.title }}</h3><p><b>{{ f.severity }}</b> · {{ f.confidence }}{% if f.module %} · {{ f.module }}{% endif %}</p><p>{{ f.description }}</p>{% if f.risk %}<p><b>Risk:</b> {{ f.risk }}</p>{% endif %}{% if f.remediation %}<p><b>Remediation:</b> {{ f.remediation }}</p>{% endif %}<p><b>OWASP:</b> {{ f.owasp_mobile_top10|join(', ') }}<br><b>MASVS:</b> {{ f.masvs|join(', ') }}<br><b>MASWE:</b> {{ f.maswe|join(', ') }}<br><b>MASTG:</b> {{ f.mastg|join(', ') }}</p><details><summary>Redacted evidence</summary><pre>{{ f.evidence_json }}</pre></details></div>{% endfor %}</body></html>""")


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
    html = _TEMPLATE.render(metadata=json.dumps(payload["metadata"], indent=2), summary=json.dumps(payload["summary"], indent=2), findings=decorated)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path
