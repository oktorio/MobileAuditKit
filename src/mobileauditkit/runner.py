from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from mobileauditkit.modules import agent_path, get_module
from mobileauditkit.redaction import permitted_runtime_evidence


@dataclass
class RuntimeObservation:
    events: list[dict[str, Any]] = field(default_factory=list)
    health: dict[str, Any] = field(
        default_factory=lambda: {"status": "unknown", "errors": [], "dropped_events": 0}
    )
    interrupted: bool = False


def _new_observation() -> RuntimeObservation:
    observation = RuntimeObservation()
    observation.health["status"] = "starting"
    return observation


def _finalize_health(result: RuntimeObservation) -> None:
    if result.health.get("errors"):
        result.health["status"] = "failed"
    elif result.interrupted:
        result.health["status"] = "incomplete"
    elif result.health.get("dropped_events", 0):
        result.health["status"] = "degraded"
    elif result.health.get("status") not in {"failed", "incomplete", "degraded"}:
        result.health["status"] = "healthy"


def run_observers_session(
    package: str,
    modules: list[str],
    seconds: float = 15.0,
    *,
    spawn: bool = False,
    max_events: int = 1000,
    frida_module: Any | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, RuntimeObservation]:
    """Run compatible read-only observers in one Frida session and observation window."""
    if seconds <= 0:
        raise ValueError("seconds must be greater than zero")
    if max_events <= 0:
        raise ValueError("max_events must be greater than zero")
    if not package.strip():
        raise ValueError("package must not be empty")
    if not modules:
        raise ValueError("at least one dynamic module is required")

    unique_modules = list(dict.fromkeys(modules))
    for module in unique_modules:
        spec = get_module(module)
        if spec.agent_filename is None:
            raise ValueError(f"Module {module} is static and cannot run in a Frida session")

    if frida_module is None:
        try:
            import frida as imported_frida
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "Frida is not installed. Install mobileauditkit dependencies first."
            ) from exc
        frida_module = imported_frida

    results = {module: _new_observation() for module in unique_modules}
    device = frida_module.get_usb_device(timeout=5)
    session = None
    scripts: list[Any] = []
    pid: int | None = None
    resumed = False

    try:
        if spawn:
            pid = device.spawn([package])
            session = device.attach(pid)
        else:
            session = device.attach(package)

        for result in results.values():
            result.health["attach"] = "ok"

        for module in unique_modules:
            result = results[module]
            source = agent_path(module).read_text(encoding="utf-8")
            try:
                script = session.create_script(source)
                result.health["script_create"] = "ok"

                def on_message(
                    message: Any,
                    _data: bytes | None,
                    *,
                    module_name: str = module,
                ) -> None:
                    current = results[module_name]
                    if message.get("type") == "send" and isinstance(
                        message.get("payload"), dict
                    ):
                        if len(current.events) >= max_events:
                            current.health["dropped_events"] += 1
                            current.health["status"] = "degraded"
                            return
                        current.events.append(
                            permitted_runtime_evidence(message["payload"])
                        )
                    elif message.get("type") == "error":
                        current.health["errors"].append("agent_error")
                        current.health["status"] = "failed"

                script.on("message", on_message)
                script.load()
                result.health["script_load"] = "ok"
                scripts.append(script)
            except Exception as exc:
                result.health["errors"].append(
                    f"script_load_error:{type(exc).__name__}"
                )
                result.health["status"] = "failed"

        if pid is not None:
            try:
                device.resume(pid)
                resumed = True
                for result in results.values():
                    result.health["resume"] = "ok"
            except Exception:
                for result in results.values():
                    result.health["resume"] = "failed"
                    result.health["errors"].append("resume_error")
                    result.health["status"] = "failed"
                raise

        try:
            sleep_fn(seconds)
        except KeyboardInterrupt:
            for result in results.values():
                result.interrupted = True
                if result.health["status"] != "failed":
                    result.health["status"] = "incomplete"

        for result in results.values():
            _finalize_health(result)
        return results
    except Exception:
        if pid is not None and not resumed:
            try:
                device.resume(pid)
                for result in results.values():
                    result.health["resume_after_failure"] = "ok"
            except Exception:
                for result in results.values():
                    result.health["resume_after_failure"] = "failed"
        raise
    finally:
        for script in reversed(scripts):
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass


def run_observer(
    package: str,
    module: str,
    seconds: float = 15.0,
    *,
    spawn: bool = False,
    max_events: int = 1000,
) -> RuntimeObservation:
    """Run one read-only Frida observer through the shared-session lifecycle."""
    return run_observers_session(
        package,
        [module],
        seconds,
        spawn=spawn,
        max_events=max_events,
    )[module]
