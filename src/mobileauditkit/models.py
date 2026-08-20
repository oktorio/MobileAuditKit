from __future__ import annotations

from datetime import UTC, datetime
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


class AssessmentStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_TESTED = "NOT_TESTED"


class EvidenceRecord(BaseModel):
    evidence_id: str
    source: str
    module: str
    test_id: str | None = None
    evidence_type: str
    sha256: str
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Finding(BaseModel):
    finding_id: str
    title: str
    description: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.OBSERVED
    module: str | None = None
    test_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
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
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AtomicTestResult(BaseModel):
    test_id: str
    title: str
    module: str
    engine: str
    status: AssessmentStatus
    observation: str
    evaluation: str
    severity: Severity | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    owasp_mobile_top10: list[str] = Field(default_factory=list)
    masvs: list[str] = Field(default_factory=list)
    maswe: list[str] = Field(default_factory=list)
    mastg: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)


class ModuleAssessment(BaseModel):
    module: str
    engine: str
    status: AssessmentStatus
    fail_threshold: Severity
    observation: str
    evaluation: str
    event_count: int = 0
    finding_count: int = 0
    highest_severity: Severity | None = None
    duration_seconds: float = 0.0
    error: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    test_ids: list[str] = Field(default_factory=list)


class CoverageSummary(BaseModel):
    total_modules: int
    pass_count: int
    fail_count: int
    inconclusive_count: int
    not_tested_count: int
    execution_coverage_percent: float
    conclusive_coverage_percent: float


class MASVSCoverageItem(BaseModel):
    control_id: str
    total_tests: int
    pass_count: int = 0
    fail_count: int = 0
    inconclusive_count: int = 0
    not_tested_count: int = 0
    execution_coverage_percent: float = 0.0
    conclusive_coverage_percent: float = 0.0


class StaticAnalysisResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    tests: list[AtomicTestResult] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssessmentReport(BaseModel):
    assessment_id: str
    tool: str = "MobileAuditKit"
    tool_version: str
    profile: str
    profile_description: str
    package: str | None = None
    apk: str | None = None
    started_at: datetime
    completed_at: datetime
    modules: list[ModuleAssessment]
    coverage: CoverageSummary
    findings: list[Finding]
    tests: list[AtomicTestResult] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    masvs_coverage: list[MASVSCoverageItem] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
