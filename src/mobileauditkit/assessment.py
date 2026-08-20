from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from mobileauditkit import __version__
from mobileauditkit.apk_config import inspect_apk_detailed
from mobileauditkit.evidence import deduplicate_evidence, make_evidence
from mobileauditkit.event_parser import findings_from_events
from mobileauditkit.models import (
    AssessmentReport,
    AssessmentStatus,
    AtomicTestResult,
    CoverageSummary,
    EvidenceRecord,
    Finding,
    MASVSCoverageItem,
    ModuleAssessment,
    Severity,
    StaticAnalysisResult,
)
from mobileauditkit.modules import get_module
from mobileauditkit.profile_loader import AssessmentProfile, ProfileModule, load_profile
from mobileauditkit.runner import run_observer
from mobileauditkit.test_registry import TestDefinition, load_registry, tests_for_module

Observer = Callable[..., list[dict[str, Any]]]
ApkInspector = Callable[[Path], StaticAnalysisResult | list[Finding]]

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
    test_results: list[AtomicTestResult] | None = None,
    error: str | None = None,
    not_tested_reason: str | None = None,
) -> ModuleAssessment:
    highest = _highest(findings)
    tests = test_results or []
    if not executed:
        status = AssessmentStatus.NOT_TESTED
        observation = not_tested_reason or "Module was not executed."
        evaluation = "No evaluation was performed because a required assessment input was unavailable."
    elif error:
        status = AssessmentStatus.INCONCLUSIVE
        observation = f"Module execution ended with an error after {duration_seconds:.2f}s."
        evaluation = "The module did not complete reliably; no PASS/FAIL conclusion is made."
    elif tests and any(item.status == AssessmentStatus.FAIL for item in tests):
        status = AssessmentStatus.FAIL
        failed = sum(item.status == AssessmentStatus.FAIL for item in tests)
        observation = f"{failed} atomic test(s) failed; {len(tests)} test result(s) were produced."
        evaluation = "FAIL because at least one atomic test reached a conclusive failing evaluation."
    elif tests and any(item.status == AssessmentStatus.INCONCLUSIVE for item in tests):
        status = AssessmentStatus.INCONCLUSIVE
        inconclusive = sum(item.status == AssessmentStatus.INCONCLUSIVE for item in tests)
        observation = f"{inconclusive} atomic test(s) require additional evidence or contextual review."
        evaluation = "INCONCLUSIVE because one or more enabled atomic tests could not be conclusively evaluated."
    elif config.requires_observation and event_count == 0 and not findings:
        status = AssessmentStatus.INCONCLUSIVE
        observation = "The module executed but produced no security-relevant evidence."
        evaluation = "Exercise more application paths or increase the observation window before concluding."
    elif highest is not None and _SEVERITY_RANK[highest] >= _SEVERITY_RANK[config.fail_threshold]:
        status = AssessmentStatus.FAIL
        observation = f"The module produced {len(findings)} finding(s); highest severity was {highest}."
        evaluation = f"At least one finding met or exceeded the profile fail threshold ({config.fail_threshold})."
    else:
        status = AssessmentStatus.PASS
        observation = f"The module executed with {event_count} runtime event(s), {len(findings)} finding record(s), and {len(tests)} atomic test result(s)."
        evaluation = "No enabled atomic test failed and no finding met the configured fail threshold in the exercised scope. PASS does not represent full MASVS compliance or prove absence of vulnerabilities."
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
        test_ids=[item.test_id for item in tests],
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


def _dynamic_test_definition(module: str) -> TestDefinition | None:
    tests = tests_for_module(module, engine="dynamic")
    return tests[0] if tests else None


def _dynamic_test_result(
    module: str,
    module_result: ModuleAssessment,
    evidence: list[EvidenceRecord],
    findings: list[Finding],
) -> AtomicTestResult | None:
    definition = _dynamic_test_definition(module)
    if definition is None:
        return None
    for finding in findings:
        if finding.test_id is None:
            finding.test_id = definition.test_id
        if not finding.evidence_ids:
            finding.evidence_ids = [record.evidence_id for record in evidence]
    return AtomicTestResult(
        test_id=definition.test_id,
        title=definition.title,
        module=module,
        engine="dynamic",
        status=module_result.status,
        observation=module_result.observation,
        evaluation=module_result.evaluation,
        severity=module_result.highest_severity,
        evidence_ids=[record.evidence_id for record in evidence],
        finding_ids=[finding.finding_id for finding in findings],
        owasp_mobile_top10=definition.owasp_mobile_top10,
        masvs=definition.masvs,
        maswe=definition.maswe,
        mastg=definition.mastg,
        cwe=definition.cwe,
    )


def _masvs_coverage(test_results: list[AtomicTestResult]) -> list[MASVSCoverageItem]:
    grouped: dict[str, list[AtomicTestResult]] = defaultdict(list)
    for test in test_results:
        for control in test.masvs:
            grouped[control].append(test)
    matrix: list[MASVSCoverageItem] = []
    for control in sorted(grouped):
        tests = grouped[control]
        total = len(tests)
        passed = sum(item.status == AssessmentStatus.PASS for item in tests)
        failed = sum(item.status == AssessmentStatus.FAIL for item in tests)
        inconclusive = sum(item.status == AssessmentStatus.INCONCLUSIVE for item in tests)
        not_tested = sum(item.status == AssessmentStatus.NOT_TESTED for item in tests)
        executed = total - not_tested
        conclusive = passed + failed
        matrix.append(
            MASVSCoverageItem(
                control_id=control,
                total_tests=total,
                pass_count=passed,
                fail_count=failed,
                inconclusive_count=inconclusive,
                not_tested_count=not_tested,
                execution_coverage_percent=round((executed / total * 100) if total else 0.0, 1),
                conclusive_coverage_percent=round((conclusive / total * 100) if total else 0.0, 1),
            )
        )
    return matrix


def run_assessment(
    *,
    package: str | None,
    profile: str | Path | AssessmentProfile = "baseline",
    apk_path: Path | None = None,
    seconds: float | None = None,
    spawn: bool = False,
    observer: Observer = run_observer,
    apk_inspector: ApkInspector = inspect_apk_detailed,
) -> AssessmentReport:
    """Execute one profile-driven authorized assessment and consolidate the results."""
    selected = profile if isinstance(profile, AssessmentProfile) else load_profile(profile)
    runtime_seconds = selected.runtime_seconds if seconds is None else seconds
    if runtime_seconds <= 0 or runtime_seconds > 3600:
        raise ValueError("seconds must be greater than zero and no more than 3600")

    started = datetime.now(UTC)
    module_results: list[ModuleAssessment] = []
    collected_findings: list[Finding] = []
    collected_tests: list[AtomicTestResult] = []
    collected_evidence: list[EvidenceRecord] = []
    static_metadata: dict[str, Any] = {}

    for module, config in selected.modules.items():
        if not config.enabled:
            continue
        spec = get_module(module)
        engine = "dynamic" if spec.agent_filename else "static"
        if engine == "static":
            if apk_path is None:
                module_results.append(_evaluate_module(module, config, engine=engine, executed=False, event_count=0, findings=[], duration_seconds=0.0, not_tested_reason="Static module requires --apk, but no APK was supplied."))
                continue
            began = time.perf_counter()
            try:
                inspected = apk_inspector(apk_path)
                if isinstance(inspected, StaticAnalysisResult):
                    findings = _deduplicate(inspected.findings)
                    tests = inspected.tests
                    evidence = inspected.evidence
                    static_metadata.update(inspected.metadata)
                else:
                    findings = _deduplicate(inspected)
                    tests = []
                    evidence = []
                duration = time.perf_counter() - began
                collected_findings.extend(findings)
                collected_tests.extend(tests)
                collected_evidence.extend(evidence)
                module_results.append(_evaluate_module(module, config, engine=engine, executed=True, event_count=0, findings=findings, duration_seconds=duration, test_results=tests))
            except Exception as exc:
                duration = time.perf_counter() - began
                module_results.append(_evaluate_module(module, config, engine=engine, executed=True, event_count=0, findings=[], duration_seconds=duration, error=f"{type(exc).__name__}: {exc}"))
            continue

        if not package:
            module_results.append(_evaluate_module(module, config, engine=engine, executed=False, event_count=0, findings=[], duration_seconds=0.0, not_tested_reason="Dynamic module requires --package, but no package was supplied."))
            continue

        began = time.perf_counter()
        try:
            events = observer(package, module, runtime_seconds, spawn=spawn)
            definition = _dynamic_test_definition(module)
            evidence = [make_evidence(source=f"frida:{module}", module=module, test_id=definition.test_id if definition else None, evidence_type="runtime-event", data=event) for event in events]
            findings = _deduplicate(findings_from_events(module, events, package))
            duration = time.perf_counter() - began
            preliminary = _evaluate_module(module, config, engine=engine, executed=True, event_count=len(events), findings=findings, duration_seconds=duration)
            dynamic_test = _dynamic_test_result(module, preliminary, evidence, findings)
            tests = [dynamic_test] if dynamic_test else []
            module_result = _evaluate_module(module, config, engine=engine, executed=True, event_count=len(events), findings=findings, duration_seconds=duration, test_results=tests)
            if dynamic_test:
                dynamic_test.status = module_result.status
                dynamic_test.observation = module_result.observation
                dynamic_test.evaluation = module_result.evaluation
            collected_findings.extend(findings)
            collected_tests.extend(tests)
            collected_evidence.extend(evidence)
            module_results.append(module_result)
        except Exception as exc:
            duration = time.perf_counter() - began
            module_result = _evaluate_module(module, config, engine=engine, executed=True, event_count=0, findings=[], duration_seconds=duration, error=f"{type(exc).__name__}: {exc}")
            definition = _dynamic_test_definition(module)
            if definition:
                collected_tests.append(AtomicTestResult(test_id=definition.test_id, title=definition.title, module=module, engine="dynamic", status=AssessmentStatus.INCONCLUSIVE, observation=module_result.observation, evaluation=module_result.evaluation, owasp_mobile_top10=definition.owasp_mobile_top10, masvs=definition.masvs, maswe=definition.maswe, mastg=definition.mastg, cwe=definition.cwe))
            module_results.append(module_result)

    findings = _deduplicate(collected_findings)
    evidence = deduplicate_evidence(collected_evidence)
    completed = datetime.now(UTC)
    inferred_package = package or static_metadata.get("package") or next((finding.package for finding in findings if finding.package), None)
    registry = load_registry()
    metadata = {
        "runtime_seconds_per_dynamic_module": runtime_seconds,
        "spawn": spawn,
        "registry_version": registry.version,
        "registry_reviewed_at": registry.reviewed_at,
        "status_semantics": "PASS means the enabled atomic/module checks were conclusively evaluated without a failure in the exercised scope; it is not a compliance certification.",
        **static_metadata,
    }
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
        tests=collected_tests,
        evidence=evidence,
        masvs_coverage=_masvs_coverage(collected_tests),
        metadata=metadata,
    )
