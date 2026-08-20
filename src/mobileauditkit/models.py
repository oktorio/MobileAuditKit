from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(StrEnum):
    OBSERVED = "Observed"
    LIKELY = "Likely"
    CONFIRMED = "Confirmed"


class Finding(BaseModel):
    finding_id: str
    title: str
    description: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.OBSERVED
    module: str | None = None
    package: str | None = None
    application_version: str | None = None
    android_version: str | None = None
    device: str | None = None
    observed_class: str | None = None
    observed_method: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    owasp_mobile_top10: list[str] = Field(default_factory=list)
    masvs: list[str] = Field(default_factory=list)
    maswe: list[str] = Field(default_factory=list)
    mastg: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    risk: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
