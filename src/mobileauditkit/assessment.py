from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from mobileauditkit import __version__
from mobileauditkit.apk_config import inspect_apk
from mobileauditkit.event_parser import findings_from_events
from mobileauditkit.models import (
    AssessmentReport,
    AssessmentStatus,
    CoverageSummary,
    Finding,
    ModuleAssessment,
    Severity,
)
from mobileauditkit.modules import get_module
from mobileauditkit.profile_loader import AssessmentProfile, ProfileModule, load_profile
from mobileauditkit.runner import run_observer

Observer = Callable[..., list[dict[str, Any]]]
ApkInspector = Callable[[Path], list[Finding]]

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _highest(findings: list[Finding]) -> Severity | None:
    if not findings:
        return None
    return max((finding.severity for finding in findings), key=_SEVERITY_RANK.__getitem__)


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.finding_id, finding)
    return list(unique.values())


def _evaluate_module(
    module: str,
    config: ProfileModule,
    *,
    engine: str,
    executed: bool,
    event_count: int,
    findings: list[Finding],
    duration_seconds: float,
    error: str | None = None,
    not_tested_reason: str | None = None,
) -> ModuleAssessment:
    highest = _highest(findings)
    if not executed:
        status = AssessmentStatus.NOT_TESTED
        observation = not_tested_reason or "Module was not executed."
        evaluation = "No evaluation was performed because a required assessment input was unavailable."
    elif error:
        status = AssessmentStatus.INCONCLUSIVE
        observation = f"Module execution ended with an error after {duration_seconds:.2f}s."
        evaluation = "The module did not complete reliably; no PASS/FAIL conclusion is made."
    elif config.requires_observation and event_count == 0 and not findings:
        status = AssessmentStatus.INCONCLUSIVE
        observation = "The module executed but produced no security-relevant evidence."
        evaluation = "Exercise more application paths or increase the observation window before concluding."
    elif highest is not None and _SEVERITY_RANK[highest] >= _SEVERITY_RANK[config.fail_threshold]:
        status = AssessmentStatus.FAIL
        observation = f"The module produced {len(findings)} finding(s); highest severity was {highest}."
        evaluation = (
            f"At least one finding met or exceeded the profile fail threshold "
            f"({config.fail_threshold})."
        )
    else:
        status = AssessmentStatus.PASS
        observation = (
            f"The module executed with {event_count} runtime event(s) and "
            f"{len(findings)} finding record(s)."
        )
        evaluation = (
            "No finding met the configured fail threshold in the exercised assessment scope. "
            "PASS does not represent full MASVS compliance or prove absence of vulnerabilities."
        )
    return ModuleAssessment(
        module=module,
        engine=engine,
        status=status,
        fail_threshold=config.fail_threshold,
        observation=observation,
        evaluation=evaluation,
        event_count=event_count,
        finding_count=len(findings),
        highest_severity=highest,
        duration_seconds=round(duration_seconds, 3),
        error=error,
        finding_ids=[finding.finding_id for finding in findings],
    )


def _coverage(results: list[ModuleAssessment]) -> CoverageSummary:
    total = len(results)
    pass_count = sum(item.status == AssessmentStatus.PASS for item in results)
    fail_count = sum(item.status == AssessmentStatus.FAIL for item in results)
    inconclusive_count = sum(item.status == AssessmentStatus.INCONCLUSIVE for item in results)
    not_tested_count = sum(item.status == AssessmentStatus.NOT_TESTED for item in results)
    executed = total - not_tested_count
    conclusive = pass_count + fail_count
    return CoverageSummary(
        total_modules=total,
        pass_count=pass_count,
        fail_count=fail_count,
        inconclusive_count=inconclusive_count,
        not_tested_count=not_tested_count,
        execution_coverage_percent=round((executed / total * 100) if total else 0.0, 1),
        conclusive_coverage_percent=round((conclusive / total * 100) if total else 0.0, 1),
    )


def run_assessment(
    *,
    package: str | None,
    profile: str | Path | AssessmentProfile = "baseline",
    apk_path: Path | None = None,
    seconds: float | None = None,
    spawn: bool = False,
    observer: Observer = run_observer,
    apk_inspector: ApkInspector = inspect_apk,
) -> AssessmentReport:
    """Execute one profile-driven authorized assessment and consolidate the results."""
    selected = profile if isinstance(profile, AssessmentProfile) else load_profile(profile)
    runtime_seconds = selected.runtime_seconds if seconds is None else seconds
    if runtime_seconds <= 0 or runtime_seconds > 3600:
        raise ValueError("seconds must be greater than zero and no more than 3600")

    started = datetime.now(UTC)
    module_results: list[ModuleAssessment] = []
    collected_findings: list[Finding] = []

    for module, config in selected.modules.items():
        if not config.enabled:
            continue
        spec = get_module(module)
        engine = "dynamic" if spec.agent_filename else "static"
        if engine == "static":
            if apk_path is None:
                module_results.append(
                    _evaluate_module(
                        module,
                        config,
                        engine=engine,
                        executed=False,
                        event_count=0,
                        findings=[],
                        duration_seconds=0.0,
                        not_tested_reason="Static module requires --apk, but no APK was supplied.",
                    )
                )
                continue
            began = time.perf_counter()
            try:
                findings = _deduplicate(apk_inspector(apk_path))
                duration = time.perf_counter() - began
                collected_findings.extend(findings)
                module_results.append(
                    _evaluate_module(
                        module,
                        config,
                        engine=engine,
                        executed=True,
                        event_count=0,
                        findings=findings,
                        duration_seconds=duration,
                    )
                )
            except Exception as exc:
                duration = time.perf_counter() - began
                module_results.append(
                    _evaluate_module(
                        module,
                        config,
                        engine=engine,
                        executed=True,
                        event_count=0,
                        findings=[],
                        duration_seconds=duration,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
            continue

        if not package:
            module_results.append(
                _evaluate_module(
                    module,
                    config,
                    engine=engine,
                    executed=False,
                    event_count=0,
                    findings=[],
                    duration_seconds=0.0,
                    not_tested_reason="Dynamic module requires --package, but no package was supplied.",
                )
            )
            continue

        began = time.perf_counter()
        try:
            events = observer(package, module, runtime_seconds, spawn=spawn)
            findings = _deduplicate(findings_from_events(module, events, package))
            duration = time.perf_counter() - began
            collected_findings.extend(findings)
            module_results.append(
                _evaluate_module(
                    module,
                    config,
                    engine=engine,
                    executed=True,
                    event_count=len(events),
                    findings=findings,
                    duration_seconds=duration,
                )
            )
        except Exception as exc:
            duration = time.perf_counter() - began
            module_results.append(
                _evaluate_module(
                    module,
                    config,
                    engine=engine,
                    executed=True,
                    event_count=0,
                    findings=[],
                    duration_seconds=duration,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    findings = _deduplicate(collected_findings)
    completed = datetime.now(UTC)
    inferred_package = package or next((finding.package for finding in findings if finding.package), None)
    return AssessmentReport(
        assessment_id=f"MAK-{uuid4().hex[:12].upper()}",
        tool_version=__version__,
        profile=selected.name,
        profile_description=selected.description,
        package=inferred_package,
        apk=apk_path.name if apk_path else None,
        started_at=started,
        completed_at=completed,
        modules=module_results,
        coverage=_coverage(module_results),
        findings=findings,
        metadata={
            "runtime_seconds_per_dynamic_module": runtime_seconds,
            "spawn": spawn,
            "status_semantics": (
                "PASS means no finding reached the profile fail threshold in the exercised scope; "
                "it is not a compliance certification."
            ),
        },
    )
