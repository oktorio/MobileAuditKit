from __future__ import annotations

import json
import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mobileauditkit.apk_config import inspect_apk
from mobileauditkit.assessment import run_assessment
from mobileauditkit.event_parser import findings_from_events
from mobileauditkit.mapping_catalog import load_mapping
from mobileauditkit.modules import MODULES, agent_path, get_module
from mobileauditkit.profile_loader import available_profiles, load_profile
from mobileauditkit.redaction import redact_text
from mobileauditkit.reporting import (
    write_assessment_html,
    write_assessment_json,
    write_html_report,
    write_json_report,
)
from mobileauditkit.runner import run_observer

app = typer.Typer(help="Defensive mobile application security assessment toolkit.")
console = Console()


@app.command()
def doctor() -> None:
    """Check local prerequisites for an authorized Android assessment lab."""
    table = Table(title="MobileAuditKit doctor")
    table.add_column("Component")
    table.add_column("Status")
    for binary in ("adb", "frida", "frida-ps", "apkanalyzer"):
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


@app.command("profiles")
def list_profiles() -> None:
    """List packaged v0.3 assessment profiles and their enabled modules."""
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
def run_module(package: str = typer.Option(..., "--package", "-p"), module: str = typer.Option(..., "--module", "-m"), seconds: float = typer.Option(15.0, min=0.1, max=3600.0), spawn: bool = typer.Option(False), json_report: Path | None = typer.Option(None), html_report: Path | None = typer.Option(None)) -> None:
    """Run one safe Frida observer and generate structured finding records."""
    if get_module(module).agent_filename is None:
        raise typer.BadParameter(f"{module} is static; use inspect-apk")
    events = run_observer(package, module, seconds, spawn=spawn)
    findings = findings_from_events(module, events, package)
    console.print(f"Observed {len(events)} event(s); generated {len(findings)} record(s).")
    metadata = {"package": package, "module": module, "event_count": len(events)}
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
) -> None:
    """Run a profile-driven multi-module assessment and create consolidated reports."""
    if not package and apk is None:
        raise typer.BadParameter("Provide --package for dynamic modules and/or --apk for static modules")
    report = run_assessment(
        package=package,
        profile=profile,
        apk_path=apk,
        seconds=seconds,
        spawn=spawn,
    )
    write_assessment_json(report, json_report)
    write_assessment_html(report, html_report)

    table = Table(title=f"Assessment {report.assessment_id} · profile={report.profile}")
    table.add_column("Module")
    table.add_column("Status")
    table.add_column("Evidence")
    table.add_column("Highest severity")
    for result in report.modules:
        table.add_row(
            result.module,
            result.status,
            f"events={result.event_count}, findings={result.finding_count}",
            result.highest_severity or "-",
        )
    console.print(table)
    console.print(
        f"Execution coverage: {report.coverage.execution_coverage_percent}% · "
        f"Conclusive coverage: {report.coverage.conclusive_coverage_percent}%"
    )
    console.print(f"JSON: {json_report}\nHTML: {html_report}")


@app.command("inspect-apk")
def inspect_apk_command(apk: Path = typer.Argument(..., exists=True, readable=True, dir_okay=False), json_report: Path | None = typer.Option(None), html_report: Path | None = typer.Option(None)) -> None:
    """Inspect AndroidManifest security configuration without executing the APK."""
    findings = inspect_apk(apk)
    metadata = {"apk": apk.name, "module": "apk-config"}
    for finding in findings:
        console.print(f"[{finding.severity}] {finding.title}")
    if json_report:
        write_json_report(findings, json_report, metadata)
    if html_report:
        write_html_report(findings, html_report, metadata)


@app.command("events-to-report")
def events_to_report(module: str, input_jsonl: Path = typer.Argument(..., exists=True, readable=True, dir_okay=False), output_json: Path | None = typer.Option(None), output_html: Path | None = typer.Option(None), package: str | None = typer.Option(None)) -> None:
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
