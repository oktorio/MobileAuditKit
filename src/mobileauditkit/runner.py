from __future__ import annotations

import time
from typing import Any

from mobileauditkit.modules import agent_path, get_module
from mobileauditkit.redaction import redact


def run_observer(
    package: str,
    module: str,
    seconds: float = 15.0,
    *,
    spawn: bool = False,
) -> list[dict[str, Any]]:
    """Run one read-only Frida observer against an authorized Android package."""
    if seconds <= 0:
        raise ValueError("seconds must be greater than zero")
    get_module(module)
    source = agent_path(module).read_text(encoding="utf-8")
    try:
        import frida
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Frida is not installed. Install mobileauditkit dependencies first."
        ) from exc

    device = frida.get_usb_device(timeout=5)
    pid: int | None = None
    if spawn:
        pid = device.spawn([package])
        session = device.attach(pid)
    else:
        session = device.attach(package)

    events: list[dict[str, Any]] = []
    script = session.create_script(source)

    def on_message(message: Any, _data: bytes | None) -> None:
        if message.get("type") == "send" and isinstance(message.get("payload"), dict):
            payload = redact(message["payload"])
            # v0.5 agents emit hook-health telemetry for the multi-module orchestrator.
            # Preserve the legacy `run` command's event stream by excluding that control signal.
            if payload.get("event") != "hook_health":
                events.append(payload)
        elif message.get("type") == "error":
            events.append({"event": "agent_error", "description": "Frida agent runtime error"})

    script.on("message", on_message)
    script.load()
    if pid is not None:
        device.resume(pid)
    try:
        time.sleep(seconds)
    finally:
        session.detach()
    return events
