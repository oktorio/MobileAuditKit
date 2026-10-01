from __future__ import annotations

import json
import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mobileauditkit.apk_config import inspect_apk_detailed
from mobileauditkit.assessment import run_assessment
from mobileauditkit.event_parser import findings_from_events
from mobileauditkit.mapping_catalog import load_mapping
from mobileauditkit.modules import MODULES, agent_path, get_module
from mobileauditkit.profile_loader import available_profiles, load_profile
from mobileauditkit.redaction import redact_text
from mobileauditkit.reporting import (
    write_assessment_html,
    write_assessment_json,
    write_assessment_sarif,
    write_html_report,
    write_json_report,
    write_static_analysis_html,
    write_static_analysis_json,
)
from mobileauditkit.runner import run_observer
from mobileauditkit.test_registry import load_registry

app = typer.Typer(help="Defensive mobile application security assessment toolkit.")
console = Console()


@app.command()
def doctor() -> None:
    """Check local prerequisites for an authorized Android assessment lab."""
    table = Table(title="MobileAuditKit doctor")
    table.add_column("Component")
    table.add_column("Status")
    for binary in ("adb", "frida", "frida-ps", "apkanalyzer", "apksigner"):
        table.add_row(binary, "OK" if shutil.which(binary) else "NOT FOUND")
    console.print(table)


@app.command("modules")
def list_modules() -> None:
    """List available assessment modules."""
    table = Table(title="Assessment modules")
    table.add_column("Module")
    table.add_column("Engine")
    table.add_column("Purpose")
    for spec in MODULES.values():
        table.add_row(spec.name, "Frida" if spec.agent_filename else "Static", spec.description)
    console.print(table)


@app.command("tests")
def list_atomic_tests(module: str | None = typer.Option(None, "--module")) -> None:
    """List MobileAuditKit atomic tests and their primary MASVS mappings."""
    registry = load_registry()
    table = Table(title=f"Atomic test registry · {registry.version}")
    table.add_column("Test ID")
    table.add_column("Engine")
    table.add_column("Module")
    table.add_column("Title")
    table.add_column("MASVS")
    for test in registry.tests:
        if module and test.module != module:
            continue
        table.add_row(test.test_id, test.engine, test.module, test.title, ", ".join(test.masvs) or "-")
    console.print(table)


@app.command("profiles")
def list_profiles() -> None:
    """List packaged assessment profiles and their enabled modules."""
    table = Table(title="Assessment profiles")
    table.add_column("Profile")
    table.add_column("Modules")
    table.add_column("Description")
    for name in available_profiles():
        profile = load_profile(name)
        enabled = ", ".join(module for module, cfg in profile.modules.items() if cfg.enabled)
        table.add_row(profile.name, enabled, profile.description)
    console.print(table)


@app.command("mappings")
def show_mappings(name: str = typer.Argument("masvs")) -> None:
    """Print one packaged OWASP mapping catalog as JSON."""
    console.print_json(data=load_mapping(name))


@app.command()
def redact(value: str) -> None:
    """Preview the built-in redaction layer."""
    console.print(redact_text(value))


@app.command()
def agent(module: str = typer.Argument(..., help="Observer module name")) -> None:
    """Print the bundled Frida agent path."""
    console.print(str(agent_path(module)))


@app.command("run")
def run_module(
    package: str = typer.Option(..., "--package", "-p"),
    module: str = typer.Option(..., "--module", "-m"),
    seconds: float = typer.Option(15.0, min=0.1, max=3600.0),
    spawn: bool = typer.Option(False),
    json_report: Path | None = typer.Option(None),
    html_report: Path | None = typer.Option(None),
) -> None:
    """Run one safe Frida observer and generate structured finding records."""
    if get_module(module).agent_filename is None:
        raise typer.BadParameter(f"{module} is static; use inspect-apk")
    observation = run_observer(package, module, seconds, spawn=spawn)
    events = observation.events
    findings = findings_from_events(module, events, package)
    health = observation.health.get("status", "unknown")
    dropped = int(observation.health.get("dropped_events", 0) or 0)
    console.print(
        f"Observed {len(events)} event(s); generated {len(findings)} record(s); "
        f"instrumentation={health}; dropped={dropped}."
    )
    metadata = {
        "package": package,
        "module": module,
        "event_count": len(events),
        "instrumentation_health": observation.health,
        "interrupted": observation.interrupted,
    }
    if json_report:
        write_json_report(findings, json_report, metadata)
    if html_report:
        write_html_report(findings, html_report, metadata)


@app.command("scan")
def scan_assessment(
    package: str | None = typer.Option(None, "--package", "-p"),
    apk: Path | None = typer.Option(None, "--apk", exists=True, readable=True, dir_okay=False),
    profile: str = typer.Option("baseline", "--profile"),
    seconds: float | None = typer.Option(None, min=0.1, max=3600.0),
    spawn: bool = typer.Option(False),
    json_report: Path = typer.Option(Path("reports/assessment.json")),
    html_report: Path = typer.Option(Path("reports/assessment.html")),
    sarif_report: Path | None = typer.Option(None, "--sarif-report"),
    sarif_location: str = typer.Option("AndroidManifest.xml", "--sarif-location", help="Repository-relative source location used for SARIF annotations."),
    exit_on_findings: bool = typer.Option(False, "--exit-on-findings", help="Exit non-zero when FAIL findings/tests are present."),
    exit_on_incomplete: bool = typer.Option(False, "--exit-on-incomplete", help="Exit non-zero when any module is INCONCLUSIVE or NOT_TESTED."),
) -> None:
    """Run a profile-driven multi-module assessment and create consolidated reports."""
    selected = load_profile(profile)
    enabled = [name for name, cfg in selected.modules.items() if cfg.enabled]
    static_required = any(get_module(name).agent_filename is None for name in enabled)
    dynamic_required = any(get_module(name).agent_filename is not None for name in enabled)
    if static_required and apk is None:
        raise typer.BadParameter(f"Profile '{selected.name}' requires --apk for static module(s).")
    if dynamic_required and not package:
        raise typer.BadParameter(f"Profile '{selected.name}' requires --package for dynamic module(s).")
    report = run_assessment(package=package, profile=selected, apk_path=apk, seconds=seconds, spawn=spawn)
    write_assessment_json(report, json_report)
    write_assessment_html(report, html_report)
    if sarif_report:
        write_assessment_sarif(report, sarif_report, default_location=sarif_location)

    table = Table(title=f"Assessment {report.assessment_id} · profile={report.profile}")
    table.add_column("Module")
    table.add_column("Status")
    table.add_column("Evidence")
    table.add_column("Instrumentation")
    table.add_column("Atomic tests")
    table.add_column("Highest severity")
    for result in report.modules:
        health = result.instrumentation_health or ("n/a" if result.engine == "static" else "unknown")
        if result.dropped_events:
            health = f"{health}; dropped={result.dropped_events}"
        table.add_row(result.module, result.status, f"events={result.event_count}, findings={result.finding_count}", health, str(len(result.test_ids)), result.highest_severity or "-")
    console.print(table)
    console.print(f"Execution coverage: {report.coverage.execution_coverage_percent}% · Conclusive coverage: {report.coverage.conclusive_coverage_percent}%")
    console.print(f"Atomic tests: {len(report.tests)} · Evidence records: {len(report.evidence)} · MASVS-linked controls: {len(report.masvs_coverage)}")
    outputs = [f"JSON: {json_report}", f"HTML: {html_report}"]
    if sarif_report:
        outputs.append(f"SARIF: {sarif_report}")
    console.print("\n".join(outputs))
    has_fail = any(item.status == "FAIL" for item in report.modules)
    incomplete = any(item.status in {"INCONCLUSIVE", "NOT_TESTED"} for item in report.modules)
    if exit_on_findings and has_fail:
        raise typer.Exit(code=2)
    if exit_on_incomplete and incomplete:
        raise typer.Exit(code=3)


@app.command("inspect-apk")
def inspect_apk_command(
    apk: Path = typer.Argument(..., exists=True, readable=True, dir_okay=False),
    json_report: Path | None = typer.Option(None),
    html_report: Path | None = typer.Option(None),
) -> None:
    """Run deep, non-executing APK static analysis with atomic test evidence."""
    result = inspect_apk_detailed(apk)
    table = Table(title=f"Static APK analysis · {apk.name}")
    table.add_column("Test")
    table.add_column("Status")
    table.add_column("Observation")
    for test in result.tests:
        table.add_row(test.test_id, test.status, test.observation)
    console.print(table)
    console.print(f"Findings: {len(result.findings)} · Evidence: {len(result.evidence)} · APK SHA-256: {result.metadata.get('apk_sha256', 'n/a')}")
    if json_report:
        write_static_analysis_json(result, json_report)
    if html_report:
        write_static_analysis_html(result, html_report)


@app.command("events-to-report")
def events_to_report(
    module: str,
    input_jsonl: Path = typer.Argument(..., exists=True, readable=True, dir_okay=False),
    output_json: Path | None = typer.Option(None),
    output_html: Path | None = typer.Option(None),
    package: str | None = typer.Option(None),
) -> None:
    """Convert previously collected redacted JSONL events into reports."""
    events = [json.loads(line) for line in input_jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
    findings = findings_from_events(module, events, package)
    metadata = {"package": package, "module": module, "source": input_jsonl.name}
    if output_json:
        write_json_report(findings, output_json, metadata)
    if output_html:
        write_html_report(findings, output_html, metadata)
    if not output_json and not output_html:
        console.print_json(data=[finding.model_dump(mode="json") for finding in findings])


if __name__ == "__main__":
    app()
