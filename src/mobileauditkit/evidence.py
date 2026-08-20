from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from mobileauditkit.models import EvidenceRecord
from mobileauditkit.redaction import redact


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def make_evidence(
    *,
    source: str,
    module: str,
    test_id: str | None,
    evidence_type: str,
    data: dict[str, Any],
) -> EvidenceRecord:
    safe = redact(data)
    payload = json.dumps(
        {
            "source": source,
            "module": module,
            "test_id": test_id,
            "evidence_type": evidence_type,
            "data": safe,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    digest = hashlib.sha256(payload).hexdigest()
    return EvidenceRecord(
        evidence_id=f"EV-{digest[:16].upper()}",
        source=source,
        module=module,
        test_id=test_id,
        evidence_type=evidence_type,
        sha256=digest,
        data=safe,
    )


def deduplicate_evidence(records: list[EvidenceRecord]) -> list[EvidenceRecord]:
    unique: dict[str, EvidenceRecord] = {}
    for record in records:
        unique.setdefault(record.evidence_id, record)
    return list(unique.values())
