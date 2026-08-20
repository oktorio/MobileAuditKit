from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from mobileauditkit.models import (
    DynamicSessionResult,
    FlowMarker,
    HookHealth,
    HookHealthState,
    RuntimeFingerprint,
)
from mobileauditkit.modules import agent_path, get_module
from mobileauditkit.redaction import redact

CommandRunner = Callable[[list[str]], str]
FingerprintCollector = Callable[[str, str | None], RuntimeFingerprint]


def _flow_marker(flow: str, phase: str) -> FlowMarker:
    timestamp = datetime.now(UTC)
    digest = hashlib.sha256(f"{flow}|{phase}|{timestamp.isoformat()}".encode()).hexdigest()
    return FlowMarker(marker_id=f"FLOW-{digest[:12].upper()}", flow=flow, phase=phase, timestamp=timestamp)


def _default_adb_runner(adb: str, args: list[str]) -> str:
    result = subprocess.run(
        [adb, *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=8,
    )
    return result.stdout.strip()


def collect_runtime_fingerprint(
    package: str,
    frida_version: str | None = None,
    *,
    adb_path: str | None = None,
    command_runner: CommandRunner | None = None,
) -> RuntimeFingerprint:
    """Collect bounded Android/app metadata without persisting the raw device serial."""
    errors: list[str] = []
    adb = adb_path or shutil.which("adb")
    run: CommandRunner

    if command_runner is None:
        if not adb:
            errors.append("adb_not_found")

            def unavailable(_: list[str]) -> str:
                raise RuntimeError("adb unavailable")

            run = unavailable
        else:

            def adb_run(args: list[str]) -> str:
                return _default_adb_runner(adb, args)

            run = adb_run
    else:
        run = command_runner

    def value(label: str, args: list[str]) -> str | None:
        try:
            text = run(args).strip()
            return text or None
        except (OSError, subprocess.SubprocessError, RuntimeError):
            errors.append(label)
            return None

    manufacturer = value("manufacturer", ["shell", "getprop", "ro.product.manufacturer"])
    model = value("model", ["shell", "getprop", "ro.product.model"])
    android_version = value("android_version", ["shell", "getprop", "ro.build.version.release"])
    api_text = value("api_level", ["shell", "getprop", "ro.build.version.sdk"])
    abi = value("abi", ["shell", "getprop", "ro.product.cpu.abi"])
    serial = value("device_serial", ["get-serialno"])
    package_dump = value("package_metadata", ["shell", "dumpsys", "package", package])

    api_level: int | None = None
    if api_text and api_text.isdigit():
        api_level = int(api_text)

    version_name: str | None = None
    version_code: str | None = None
    if package_dump:
        name_match = re.search(r"\bversionName=([^\s]+)", package_dump)
        code_match = re.search(r"\bversionCode=(\d+)", package_dump)
        version_name = name_match.group(1) if name_match else None
        version_code = code_match.group(1) if code_match else None

    device_id_hash = hashlib.sha256(serial.encode()).hexdigest()[:16].upper() if serial else None
    canonical = {
        "package": package,
        "app_version_name": version_name,
        "app_version_code": version_code,
        "android_version": android_version,
        "api_level": api_level,
        "manufacturer": manufacturer,
        "model": model,
        "abi": abi,
        "frida_version": frida_version,
        "device_id_hash": device_id_hash,
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return RuntimeFingerprint(
        fingerprint_id=f"FP-{digest[:16].upper()}",
        package=package,
        app_version_name=version_name,
        app_version_code=version_code,
        android_version=android_version,
        api_level=api_level,
        manufacturer=manufacturer,
        model=model,
        abi=abi,
        frida_version=frida_version,
        device_id_hash=device_id_hash,
        collection_errors=sorted(set(errors)),
    )


def _apply_health_signal(health: HookHealth, payload: dict[str, Any]) -> None:
    health.signal_received = True
    health.hooks_attempted = max(0, int(payload.get("hooks_attempted", 0) or 0))
    health.hooks_installed = max(0, int(payload.get("hooks_installed", 0) or 0))
    requested = str(payload.get("state", "")).upper()
    if requested == HookHealthState.READY:
        state = HookHealthState.READY
    elif requested == HookHealthState.ERROR:
        state = HookHealthState.ERROR
    else:
        state = HookHealthState.DEGRADED
    if health.hooks_installed <= 0:
        state = HookHealthState.DEGRADED
    elif health.hooks_attempted and health.hooks_installed < health.hooks_attempted:
        state = HookHealthState.DEGRADED
    health.state = state
    if state == HookHealthState.READY:
        health.observation = (
            f"Observer reported {health.hooks_installed}/{health.hooks_attempted} hook group(s) installed."
        )
    elif state == HookHealthState.DEGRADED:
        health.observation = (
            f"Observer reported partial hook coverage: {health.hooks_installed}/{health.hooks_attempted} hook group(s) installed."
        )
    else:
        health.observation = "Observer reported a runtime hook error."


def run_observers_session(
    package: str,
    modules: list[str],
    seconds: float = 20.0,
    *,
    spawn: bool = False,
    flow: str = "default",
    frida_module: Any | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    fingerprint_collector: FingerprintCollector = collect_runtime_fingerprint,
) -> DynamicSessionResult:
    """Load multiple read-only Frida observers into one authorized app session."""
    if seconds <= 0 or seconds > 3600:
        raise ValueError("seconds must be greater than zero and no more than 3600")
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
            raise RuntimeError("Frida is not installed. Install MobileAuditKit dependencies first.") from exc
        frida_module = imported_frida

    frida_version = getattr(frida_module, "__version__", None)
    try:
        fingerprint = fingerprint_collector(package, frida_version)
    except Exception:
        fingerprint = RuntimeFingerprint(
            fingerprint_id="FP-UNAVAILABLE",
            package=package,
            frida_version=frida_version,
            collector="unavailable",
            collection_errors=["fingerprint_collector_error"],
        )

    began = time.perf_counter()
    events: dict[str, list[dict[str, Any]]] = {module: [] for module in unique_modules}
    health: dict[str, HookHealth] = {
        module: HookHealth(module=module) for module in unique_modules
    }
    errors: list[str] = []
    flows: list[FlowMarker] = []
    scripts: list[Any] = []
    session: Any | None = None
    pid: int | None = None

    device = frida_module.get_usb_device(timeout=5)
    if spawn:
        pid = device.spawn([package])
        session = device.attach(pid)
    else:
        session = device.attach(package)

    try:
        for module in unique_modules:
            source = agent_path(module).read_text(encoding="utf-8")
            current = health[module]
            try:
                script = session.create_script(source)

                def on_message(
                    message: Any,
                    _data: bytes | None,
                    *,
                    module_name: str = module,
                ) -> None:
                    module_health = health[module_name]
                    if message.get("type") == "send" and isinstance(message.get("payload"), dict):
                        payload = redact(message["payload"])
                        if payload.get("event") == "hook_health":
                            _apply_health_signal(module_health, payload)
                            return
                        payload.setdefault("flow", flow)
                        payload.setdefault("observed_at", datetime.now(UTC).isoformat())
                        events[module_name].append(payload)
                        module_health.security_event_count = len(events[module_name])
                    elif message.get("type") == "error":
                        module_health.error_count += 1
                        module_health.state = HookHealthState.ERROR
                        module_health.observation = "Frida reported an observer script runtime error."
                        errors.append(f"{module_name}:agent_runtime_error")

                script.on("message", on_message)
                current.state = HookHealthState.NO_SIGNAL
                current.observation = "Observer script is loading; waiting for hook-health signal."
                script.load()
                current.script_loaded = True
                if not current.signal_received:
                    current.observation = "Observer script loaded; waiting for hook-health signal."
                scripts.append(script)
            except Exception:
                current.error_count += 1
                current.state = HookHealthState.ERROR
                current.observation = "Observer script could not be loaded."
                errors.append(f"{module}:script_load_error")

        if pid is not None:
            device.resume(pid)

        flows.append(_flow_marker(flow, "start"))
        sleep_fn(seconds)
        flows.append(_flow_marker(flow, "end"))
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                errors.append("session_detach_error")

    for module, item in health.items():
        item.security_event_count = len(events[module])
        if item.script_loaded and not item.signal_received and item.state != HookHealthState.ERROR:
            item.state = HookHealthState.NO_SIGNAL
            item.observation = (
                "Observer script loaded but no hook-health signal was received; negative observations are inconclusive."
            )

    return DynamicSessionResult(
        package=package,
        modules=unique_modules,
        events=events,
        hook_health=health,
        fingerprint=fingerprint,
        flows=flows,
        duration_seconds=round(time.perf_counter() - began, 3),
        errors=errors,
    )
