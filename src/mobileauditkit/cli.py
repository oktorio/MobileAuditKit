from __future__ import annotations

import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mobileauditkit.redaction import redact_text

app = typer.Typer(help="Defensive mobile application security assessment toolkit.")
console = Console()

MODULES = {
    "crypto": "Observe cryptographic algorithm/mode use without capturing keys or data",
    "storage": "Observe storage API use without dumping application data",
    "network": "Observe HTTP/TLS security configuration and validation behavior",
    "authentication": "Observe platform authentication APIs without bypassing them",
    "webview": "Observe security-relevant WebView configuration",
    "privacy": "Observe clipboard/logging/privacy-sensitive API use with redaction",
    "resilience": "Observe presence/activation of integrity, root and anti-debug controls",
}


@app.command()
def doctor() -> None:
    """Check local prerequisites for an authorized Android assessment lab."""
    table = Table(title="MobileAuditKit doctor")
    table.add_column("Component")
    table.add_column("Status")
    for binary in ("adb", "frida", "frida-ps"):
        table.add_row(binary, "OK" if shutil.which(binary) else "NOT FOUND")
    console.print(table)


@app.command("modules")
def list_modules() -> None:
    """List available/planned assessment modules."""
    table = Table(title="Assessment modules")
    table.add_column("Module")
    table.add_column("Purpose")
    for name, purpose in MODULES.items():
        table.add_row(name, purpose)
    console.print(table)


@app.command()
def redact(value: str) -> None:
    """Preview the built-in sensitive-data redaction layer."""
    console.print(redact_text(value))


@app.command()
def agent(module: str = typer.Argument(..., help="Observer module name")) -> None:
    """Print the bundled Frida agent path for an observer module."""
    if module not in MODULES:
        raise typer.BadParameter(f"Unknown module: {module}")
    root = Path(__file__).resolve().parents[2]
    candidate = root / "scripts" / f"m10_cryptography/{module}_observer.js"
    if module != "crypto" or not candidate.exists():
        console.print(f"[yellow]{module} observer is planned for a subsequent increment.[/yellow]")
        raise typer.Exit(code=2)
    console.print(str(candidate))


if __name__ == "__main__":
    app()
