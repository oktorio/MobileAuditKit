from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from mobileauditkit.modules import agent_path, get_module
from mobileauditkit.redaction import permitted_runtime_evidence


@dataclass
class RuntimeObservation:
    events: list[dict[str, Any]] = field(default_factory=list)
    health: dict[str, Any] = field(
        default_factory=lambda: {"status": "unknown", "errors": [], "dropped_events": 0}
    )
    interrupted: bool = False


def run_observer(
    package: str,
    module: str,
    seconds: float = 15.0,
    *,
    spawn: bool = False,
    max_events: int = 1000,
) -> RuntimeObservation:
    """Run one read-only Frida observer with bounded collection and lifecycle cleanup."""
    if seconds <= 0:
        raise ValueError("seconds must be greater than zero")
    if max_events <= 0:
        raise ValueError("max_events must be greater than zero")
    get_module(module)
    source = agent_path(module).read_text(encoding="utf-8")
    try:
        import frida
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Frida is not installed. Install mobileauditkit dependencies first."
        ) from exc

    device = frida.get_usb_device(timeout=5)
    session = None
    script = None
    pid: int | None = None
    resumed = False
    result = RuntimeObservation()
    result.health["status"] = "starting"

    try:
        if spawn:
            pid = device.spawn([package])
            session = device.attach(pid)
        else:
            session = device.attach(package)
        result.health["attach"] = "ok"

        script = session.create_script(source)
        result.health["script_create"] = "ok"

        def on_message(message: Any, _data: bytes | None) -> None:
            if message.get("type") == "send" and isinstance(message.get("payload"), dict):
                if len(result.events) >= max_events:
                    result.health["dropped_events"] += 1
                    result.health["status"] = "degraded"
                    return
                result.events.append(permitted_runtime_evidence(message["payload"]))
            elif message.get("type") == "error":
                result.health["errors"].append("agent_error")
                result.health["status"] = "failed"

        script.on("message", on_message)
        script.load()
        result.health["script_load"] = "ok"

        if pid is not None:
            try:
                device.resume(pid)
                resumed = True
                result.health["resume"] = "ok"
            except Exception:
                result.health["resume"] = "failed"
                raise

        result.health["status"] = "healthy"
        try:
            time.sleep(seconds)
        except KeyboardInterrupt:
            result.interrupted = True
            result.health["status"] = "incomplete"

        if result.health["dropped_events"]:
            result.health["status"] = "degraded"
        if result.health["errors"]:
            result.health["status"] = "failed"
        return result
    except Exception:
        if pid is not None and not resumed:
            try:
                device.resume(pid)
                result.health["resume_after_failure"] = "ok"
            except Exception:
                result.health["resume_after_failure"] = "failed"
        raise
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
