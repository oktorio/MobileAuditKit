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
from mobileauditkit.models import (
    AssessmentReport,
    AssessmentStatus,
    AtomicTestResult,
    CoverageSummary,
    DynamicSessionResult,
    EvidenceRecord,
    Finding,
    HookHealth,
    HookHealthState,
    MASVSCoverageItem,
    ModuleAssessment,
    Severity,
    StaticAnalysisResult,
)
from mobileauditkit.modules import get_module
from mobileauditkit.profile_loader import AssessmentProfile, ProfileModule, load_profile
from mobileauditkit.runner import run_observer
from mobileauditkit.runtime_evaluation import evaluate_runtime_module
from mobileauditkit.runtime_orchestrator import run_observers_session
from mobileauditkit.test_registry import TestDefinition, load_registry, tests_for_module

Observer = Callable[..., list[dict[str, Any]]]
ApkInspector = Callable[[Path], StaticAnalysisResult | list[Finding]]
SessionRunner = Callable[..., DynamicSessionResult]

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


def _registry_result(
    definition: TestDefinition,
    status: AssessmentStatus,
    observation: str,
    evaluation: str,
) -> AtomicTestResult:
    return AtomicTestResult(
        test_id=definition.test_id,
        title=definition.title,
        module=definition.module,
        engine=definition.engine,
        status=status,
        observation=observation,
        evaluation=evaluation,
        owasp_mobile_top10=definition.owasp_mobile_top10,
        masvs=definition.masvs,
        maswe=definition.maswe,
        mastg=definition.mastg,
        cwe=definition.cwe,
    )


def _complete_module_tests(
    module: str,
    engine: str,
    existing: list[AtomicTestResult],
    *,
    missing_status: AssessmentStatus,
    observation: str,
    evaluation: str,
) -> list[AtomicTestResult]:
    existing_by_id = {item.test_id: item for item in existing}
    definitions = tests_for_module(module, engine=engine)
    definition_ids = {item.test_id for item in definitions}
    completed = [
        existing_by_id.get(definition.test_id)
        or _registry_result(definition, missing_status, observation, evaluation)
        for definition in definitions
    ]
    completed.extend(item for item in existing if item.test_id not in definition_ids)
    return completed


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
    hook_health: HookHealth | None = None,
    error: str | None = None,
    not_tested_reason: str | None = None,
) -> ModuleAssessment:
    highest = _highest(findings)
    tests = test_results or []
    unmapped_threshold_findings = [
        finding
        for finding in findings
        if finding.test_id is None
        and _SEVERITY_RANK[finding.severity] >= _SEVERITY_RANK[config.fail_threshold]
    ]

    if not executed:
        status = AssessmentStatus.NOT_TESTED
        observation = not_tested_reason or "Module was not executed."
        evaluation = (
            "No evaluation was performed because a required assessment input was unavailable."
        )
    elif error:
        status = AssessmentStatus.INCONCLUSIVE
        observation = f"Module execution ended with an error after {duration_seconds:.2f}s."
        evaluation = "The module did not complete reliably; no PASS/FAIL conclusion is made."
    elif tests and any(item.status == AssessmentStatus.FAIL for item in tests):
        status = AssessmentStatus.FAIL
        failed = sum(item.status == AssessmentStatus.FAIL for item in tests)
        observation = f"{failed} atomic test(s) failed; {len(tests)} test result(s) were produced."
        evaluation = "FAIL because at least one atomic test reached a conclusive failing evaluation."
    elif unmapped_threshold_findings:
        status = AssessmentStatus.FAIL
        observation = (
            f"{len(unmapped_threshold_findings)} legacy/unmapped finding(s) met or exceeded "
            "the profile threshold."
        )
        evaluation = (
            "A findings-only compatibility result met or exceeded the profile fail threshold "
            f"({config.fail_threshold})."
        )
    elif tests and any(item.status == AssessmentStatus.INCONCLUSIVE for item in tests):
        status = AssessmentStatus.INCONCLUSIVE
        inconclusive = sum(item.status == AssessmentStatus.INCONCLUSIVE for item in tests)
        observation = (
            f"{inconclusive} atomic test(s) require additional evidence or contextual review."
        )
        evaluation = (
            "INCONCLUSIVE because one or more enabled atomic tests could not be "
            "conclusively evaluated."
        )
    elif engine == "dynamic" and config.requires_observation and event_count == 0 and not findings:
        status = AssessmentStatus.INCONCLUSIVE
        observation = "The module executed but produced no security-relevant evidence."
        evaluation = (
            "Exercise more application paths or increase the observation window before concluding."
        )
    else:
        status = AssessmentStatus.PASS
        observation = (
            f"The module executed with {event_count} runtime event(s), {len(findings)} finding "
            f"record(s), and {len(tests)} atomic test result(s)."
        )
        evaluation = (
            "No enabled atomic test failed in the exercised scope. PASS is scoped and does not "
            "represent full MASVS compliance or prove absence of vulnerabilities."
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
        test_ids=[item.test_id for item in tests],
        hook_health=hook_health,
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
                execution_coverage_percent=round(
                    (executed / total * 100) if total else 0.0, 1
                ),
                conclusive_coverage_percent=round(
                    (conclusive / total * 100) if total else 0.0, 1
                ),
            )
        )
    return matrix


def _legacy_health(module: str, event_count: int) -> HookHealth:
    return HookHealth(
        module=module,
        state=HookHealthState.READY,
        script_loaded=True,
        signal_received=True,
        hooks_attempted=1,
        hooks_installed=1,
        security_event_count=event_count,
        observation=(
            "Custom/legacy observer injection treated as a healthy test-harness source for "
            "compatibility."
        ),
    )


def run_assessment(
    *,
    package: str | None,
    profile: str | Path | AssessmentProfile = "baseline",
    apk_path: Path | None = None,
    seconds: float | None = None,
    spawn: bool = False,
    flow: str = "default",
    observer: Observer = run_observer,
    session_runner: SessionRunner = run_observers_session,
    apk_inspector: ApkInspector = inspect_apk_detailed,
) -> AssessmentReport:
    """Execute a profile-driven authorized assessment with single-session dynamic orchestration."""
    selected = profile if isinstance(profile, AssessmentProfile) else load_profile(profile)
    runtime_seconds = selected.runtime_seconds if seconds is None else seconds
    if runtime_seconds <= 0 or runtime_seconds > 3600:
        raise ValueError("seconds must be greater than zero and no more than 3600")
    if not flow.strip():
        raise ValueError("flow must not be empty")

    started = datetime.now(UTC)
    module_results: list[ModuleAssessment] = []
    collected_findings: list[Finding] = []
    collected_tests: list[AtomicTestResult] = []
    collected_evidence: list[EvidenceRecord] = []
    static_metadata: dict[str, Any] = {}

    dynamic_modules = [
        module
        for module, config in selected.modules.items()
        if config.enabled and get_module(module).agent_filename is not None
    ]
    use_session_orchestrator = observer is run_observer
    runtime_session: DynamicSessionResult | None = None
    runtime_session_error: str | None = None

    if package and dynamic_modules and use_session_orchestrator:
        try:
            runtime_session = session_runner(
                package,
                dynamic_modules,
                runtime_seconds,
                spawn=spawn,
                flow=flow,
            )
        except Exception as exc:
            runtime_session_error = f"{type(exc).__name__}: {exc}"

    for module, config in selected.modules.items():
        if not config.enabled:
            continue
        spec = get_module(module)
        engine = "dynamic" if spec.agent_filename else "static"

        if engine == "static":
            if apk_path is None:
                reason = "Static module requires --apk, but no APK was supplied."
                tests = _complete_module_tests(
                    module,
                    engine,
                    [],
                    missing_status=AssessmentStatus.NOT_TESTED,
                    observation=reason,
                    evaluation=(
                        "Atomic test was not executed because the required APK input was unavailable."
                    ),
                )
                collected_tests.extend(tests)
                module_results.append(
                    _evaluate_module(
                        module,
                        config,
                        engine=engine,
                        executed=False,
                        event_count=0,
                        findings=[],
                        duration_seconds=0.0,
                        test_results=tests,
                        not_tested_reason=reason,
                    )
                )
                continue

            began = time.perf_counter()
            try:
                inspected = apk_inspector(apk_path)
                if isinstance(inspected, StaticAnalysisResult):
                    findings = _deduplicate(inspected.findings)
                    tests = _complete_module_tests(
                        module,
                        engine,
                        inspected.tests,
                        missing_status=AssessmentStatus.INCONCLUSIVE,
                        observation=(
                            "Static inspector did not produce a result for this registry test."
                        ),
                        evaluation=(
                            "Atomic test coverage is incomplete; no PASS/FAIL conclusion is made "
                            "for this test."
                        ),
                    )
                    evidence = inspected.evidence
                    static_metadata.update(inspected.metadata)
                else:
                    findings = _deduplicate(inspected)
                    tests = _complete_module_tests(
                        module,
                        engine,
                        [],
                        missing_status=AssessmentStatus.INCONCLUSIVE,
                        observation=(
                            "Findings-only static inspector did not provide atomic test results."
                        ),
                        evaluation=(
                            "Atomic test coverage cannot be concluded from the legacy "
                            "findings-only interface."
                        ),
                    )
                    evidence = []

                duration = time.perf_counter() - began
                collected_findings.extend(findings)
                collected_tests.extend(tests)
                collected_evidence.extend(evidence)
                module_results.append(
                    _evaluate_module(
                        module,
                        config,
                        engine=engine,
                        executed=True,
                        event_count=0,
                        findings=findings,
                        duration_seconds=duration,
                        test_results=tests,
                    )
                )
            except Exception as exc:
                duration = time.perf_counter() - began
                error = f"{type(exc).__name__}: {exc}"
                tests = _complete_module_tests(
                    module,
                    engine,
                    [],
                    missing_status=AssessmentStatus.INCONCLUSIVE,
                    observation="Static module execution failed.",
                    evaluation="Atomic tests could not be reliably evaluated.",
                )
                collected_tests.extend(tests)
                module_results.append(
                    _evaluate_module(
                        module,
                        config,
                        engine=engine,
                        executed=True,
                        event_count=0,
                        findings=[],
                        duration_seconds=duration,
                        test_results=tests,
                        error=error,
                    )
                )
            continue

        if not package:
            reason = "Dynamic module requires --package, but no package was supplied."
            tests = _complete_module_tests(
                module,
                engine,
                [],
                missing_status=AssessmentStatus.NOT_TESTED,
                observation=reason,
                evaluation=(
                    "Atomic test was not executed because the required package input was unavailable."
                ),
            )
            collected_tests.extend(tests)
            module_results.append(
                _evaluate_module(
                    module,
                    config,
                    engine=engine,
                    executed=False,
                    event_count=0,
                    findings=[],
                    duration_seconds=0.0,
                    test_results=tests,
                    not_tested_reason=reason,
                )
            )
            continue

        if use_session_orchestrator:
            if runtime_session is None:
                tests = _complete_module_tests(
                    module,
                    engine,
                    [],
                    missing_status=AssessmentStatus.INCONCLUSIVE,
                    observation="The shared Frida session could not be established.",
                    evaluation="Runtime atomic tests could not be executed reliably.",
                )
                collected_tests.extend(tests)
                module_results.append(
                    _evaluate_module(
                        module,
                        config,
                        engine=engine,
                        executed=True,
                        event_count=0,
                        findings=[],
                        duration_seconds=0.0,
                        test_results=tests,
                        error=runtime_session_error or "runtime session unavailable",
                    )
                )
                continue

            health = runtime_session.hook_health[module]
            events = runtime_session.events.get(module, [])
            analysis = evaluate_runtime_module(module, events, health, package)
            findings = _deduplicate(analysis.findings)
            tests = _complete_module_tests(
                module,
                engine,
                analysis.tests,
                missing_status=AssessmentStatus.INCONCLUSIVE,
                observation="Runtime evaluator did not produce a result for this registry test.",
                evaluation="No PASS/FAIL conclusion is made for missing runtime test output.",
            )
            collected_findings.extend(findings)
            collected_tests.extend(tests)
            collected_evidence.extend(analysis.evidence)
            module_results.append(
                _evaluate_module(
                    module,
                    config,
                    engine=engine,
                    executed=True,
                    event_count=len(events),
                    findings=findings,
                    duration_seconds=runtime_session.duration_seconds,
                    test_results=tests,
                    hook_health=health,
                )
            )
            continue

        began = time.perf_counter()
        try:
            events = observer(package, module, runtime_seconds, spawn=spawn)
            health = _legacy_health(module, len(events))
            analysis = evaluate_runtime_module(module, events, health, package)
            findings = _deduplicate(analysis.findings)
            tests = _complete_module_tests(
                module,
                engine,
                analysis.tests,
                missing_status=AssessmentStatus.INCONCLUSIVE,
                observation="Custom observer did not produce complete atomic runtime output.",
                evaluation="No PASS/FAIL conclusion is made for missing runtime test output.",
            )
            duration = time.perf_counter() - began
            collected_findings.extend(findings)
            collected_tests.extend(tests)
            collected_evidence.extend(analysis.evidence)
            module_results.append(
                _evaluate_module(
                    module,
                    config,
                    engine=engine,
                    executed=True,
                    event_count=len(events),
                    findings=findings,
                    duration_seconds=duration,
                    test_results=tests,
                    hook_health=health,
                )
            )
        except Exception as exc:
            duration = time.perf_counter() - began
            health = HookHealth(
                module=module,
                state=HookHealthState.ERROR,
                error_count=1,
                observation="Custom observer execution failed.",
            )
            tests = _complete_module_tests(
                module,
                engine,
                [],
                missing_status=AssessmentStatus.INCONCLUSIVE,
                observation="Runtime module execution failed.",
                evaluation="Atomic tests could not be reliably evaluated.",
            )
            collected_tests.extend(tests)
            module_results.append(
                _evaluate_module(
                    module,
                    config,
                    engine=engine,
                    executed=True,
                    event_count=0,
                    findings=[],
                    duration_seconds=duration,
                    test_results=tests,
                    hook_health=health,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    runtime_fingerprint = runtime_session.fingerprint if runtime_session else None
    flows = runtime_session.flows if runtime_session else []
    if runtime_fingerprint is not None:
        collected_evidence.append(
            make_evidence(
                source="runtime-fingerprint",
                module="runtime",
                test_id=None,
                evidence_type="runtime-fingerprint",
                data=runtime_fingerprint.model_dump(mode="json"),
            )
        )
    for marker in flows:
        collected_evidence.append(
            make_evidence(
                source=f"flow:{marker.flow}",
                module="runtime",
                test_id=None,
                evidence_type="flow-marker",
                data=marker.model_dump(mode="json"),
            )
        )

    findings = _deduplicate(collected_findings)
    evidence = deduplicate_evidence(collected_evidence)
    completed = datetime.now(UTC)
    inferred_package = (
        package
        or static_metadata.get("package")
        or next((finding.package for finding in findings if finding.package), None)
    )
    registry = load_registry()
    metadata = {
        "runtime_seconds": runtime_seconds,
        "spawn": spawn,
        "flow": flow,
        "dynamic_orchestrator": (
            "single-session"
            if use_session_orchestrator and dynamic_modules
            else "legacy/custom-observer"
        ),
        "registry_version": registry.version,
        "registry_reviewed_at": registry.reviewed_at,
        "status_semantics": (
            "PASS is scoped to enabled atomic tests, the exercised flow, and sufficient "
            "evidence/hook health. It is not a MASVS compliance certification or proof of "
            "vulnerability absence."
        ),
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
        runtime_fingerprint=runtime_fingerprint,
        flows=flows,
        metadata=metadata,
    )
