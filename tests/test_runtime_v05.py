from __future__ import annotations

from typing import Any

from mobileauditkit.models import (
    AssessmentStatus,
    HookHealth,
    HookHealthState,
    RuntimeFingerprint,
)
from mobileauditkit.runtime_evaluation import evaluate_runtime_module
from mobileauditkit.runtime_orchestrator import (
    collect_runtime_fingerprint,
    run_observers_session,
)


class FakeScript:
    def __init__(self, module: str, payloads: list[dict[str, Any]]) -> None:
        self.module = module
        self.payloads = payloads
        self.callback = None
        self.loaded = False

    def on(self, signal: str, callback) -> None:
        assert signal == "message"
        self.callback = callback

    def load(self) -> None:
        self.loaded = True
        assert self.callback is not None
        self.callback(
            {
                "type": "send",
                "payload": {
                    "event": "hook_health",
                    "state": "READY",
                    "hooks_attempted": 2,
                    "hooks_installed": 2,
                },
            },
            None,
        )
        for payload in self.payloads:
            self.callback({"type": "send", "payload": payload}, None)


class FakeSession:
    def __init__(self, payloads: dict[str, list[dict[str, Any]]]) -> None:
        self.payloads = payloads
        self.created = 0
        self.detached = 0

    def create_script(self, source: str) -> FakeScript:
        self.created += 1
        module = next(name for name in self.payloads if f"module: '{name}'" in source)
        return FakeScript(module, self.payloads[module])

    def detach(self) -> None:
        self.detached += 1


class FakeDevice:
    def __init__(self, session: FakeSession) -> None:
        self.session = session
        self.attach_calls = 0
        self.spawn_calls = 0
        self.resume_calls = 0

    def attach(self, target) -> FakeSession:
        self.attach_calls += 1
        return self.session

    def spawn(self, argv: list[str]) -> int:
        self.spawn_calls += 1
        assert argv == ["com.example"]
        return 4242

    def resume(self, pid: int) -> None:
        self.resume_calls += 1
        assert pid == 4242


class FakeFrida:
    __version__ = "17.test"

    def __init__(self, device: FakeDevice) -> None:
        self.device = device
        self.device_calls = 0

    def get_usb_device(self, timeout: int) -> FakeDevice:
        self.device_calls += 1
        assert timeout == 5
        return self.device


def fingerprint(package: str, frida_version: str | None) -> RuntimeFingerprint:
    return RuntimeFingerprint(
        fingerprint_id="FP-FIXTURE",
        package=package,
        app_version_name="1.2.3",
        app_version_code="123",
        android_version="16",
        api_level=36,
        manufacturer="Example",
        model="LabDevice",
        abi="arm64-v8a",
        frida_version=frida_version,
        device_id_hash="ABCDEF0123456789",
    )


def test_single_session_loads_multiple_observers_once_and_marks_flow() -> None:
    payloads = {
        "network": [{"event": "network_pinning", "validation_modified": False}],
        "crypto": [{"event": "crypto_algorithm", "algorithm": "AES/GCM/NoPadding"}],
    }
    session = FakeSession(payloads)
    device = FakeDevice(session)
    frida = FakeFrida(device)
    sleeps: list[float] = []

    result = run_observers_session(
        "com.example",
        ["network", "crypto"],
        3,
        flow="login",
        frida_module=frida,
        sleep_fn=sleeps.append,
        fingerprint_collector=fingerprint,
    )

    assert device.attach_calls == 1
    assert session.created == 2
    assert session.detached == 1
    assert sleeps == [3]
    assert result.fingerprint and result.fingerprint.frida_version == "17.test"
    assert [marker.phase for marker in result.flows] == ["start", "end"]
    assert all(marker.flow == "login" for marker in result.flows)
    assert result.events["network"][0]["flow"] == "login"
    assert result.hook_health["network"].state == HookHealthState.READY
    assert result.hook_health["crypto"].hooks_installed == 2


def test_spawn_is_resumed_once_after_all_scripts_are_loaded() -> None:
    payloads = {"network": []}
    session = FakeSession(payloads)
    device = FakeDevice(session)
    frida = FakeFrida(device)
    run_observers_session(
        "com.example",
        ["network"],
        1,
        spawn=True,
        frida_module=frida,
        sleep_fn=lambda _: None,
        fingerprint_collector=fingerprint,
    )
    assert device.spawn_calls == 1
    assert device.attach_calls == 1
    assert device.resume_calls == 1


def test_crypto_atomic_tests_fail_and_pass_from_direct_observation() -> None:
    ready = HookHealth(
        module="crypto",
        state=HookHealthState.READY,
        script_loaded=True,
        signal_received=True,
        hooks_attempted=3,
        hooks_installed=3,
    )
    bad = evaluate_runtime_module(
        "crypto",
        [{"event": "crypto_algorithm", "algorithm": "SHA-1"}],
        ready,
        "com.example",
    )
    statuses = {item.test_id: item.status for item in bad.tests}
    assert statuses["MAK-DYN-0201"] == AssessmentStatus.FAIL

    good = evaluate_runtime_module(
        "crypto",
        [{"event": "crypto_algorithm", "algorithm": "AES/GCM/NoPadding"}],
        ready,
        "com.example",
    )
    statuses = {item.test_id: item.status for item in good.tests}
    assert statuses == {
        "MAK-DYN-0201": AssessmentStatus.PASS,
        "MAK-DYN-0202": AssessmentStatus.PASS,
    }

    bare_aes = evaluate_runtime_module(
        "crypto",
        [{"event": "crypto_algorithm", "algorithm": "AES"}],
        ready,
        "com.example",
    )
    bare_statuses = {item.test_id: item.status for item in bare_aes.tests}
    assert bare_statuses["MAK-DYN-0202"] == AssessmentStatus.FAIL

    rsa_placeholder = evaluate_runtime_module(
        "crypto",
        [{"event": "crypto_algorithm", "algorithm": "RSA/ECB/OAEPPadding"}],
        ready,
        "com.example",
    )
    rsa_statuses = {item.test_id: item.status for item in rsa_placeholder.tests}
    assert rsa_statuses["MAK-DYN-0202"] == AssessmentStatus.PASS


def test_negative_observation_is_inconclusive_without_hook_health() -> None:
    health = HookHealth(
        module="network",
        state=HookHealthState.NO_SIGNAL,
        script_loaded=True,
        signal_received=False,
    )
    result = evaluate_runtime_module(
        "network",
        [{"event": "network_pinning", "validation_modified": False}],
        health,
        "com.example",
    )
    statuses = {item.test_id: item.status for item in result.tests}
    assert statuses["MAK-DYN-0220"] == AssessmentStatus.INCONCLUSIVE
    assert statuses["MAK-DYN-0222"] == AssessmentStatus.PASS


def test_contextual_biometric_observation_does_not_overclaim_failure() -> None:
    health = HookHealth(
        module="authentication",
        state=HookHealthState.READY,
        script_loaded=True,
        signal_received=True,
        hooks_attempted=2,
        hooks_installed=2,
    )
    result = evaluate_runtime_module(
        "authentication",
        [{"event": "biometric_authentication", "crypto_bound": False}],
        health,
        "com.example",
    )
    assert result.tests[0].status == AssessmentStatus.INCONCLUSIVE
    assert result.findings[0].severity.value == "MEDIUM"
    assert result.findings[0].test_id == "MAK-DYN-0230"


def test_fingerprint_hashes_serial_and_keeps_only_bounded_metadata() -> None:
    values = {
        ("shell", "getprop", "ro.product.manufacturer"): "Google",
        ("shell", "getprop", "ro.product.model"): "Pixel Lab",
        ("shell", "getprop", "ro.build.version.release"): "16",
        ("shell", "getprop", "ro.build.version.sdk"): "36",
        ("shell", "getprop", "ro.product.cpu.abi"): "arm64-v8a",
        ("get-serialno",): "SERIAL-SECRET",
        (
            "shell",
            "dumpsys",
            "package",
            "com.example",
        ): "versionCode=42 minSdk=26 targetSdk=36\nversionName=4.2.0\n",
    }

    result = collect_runtime_fingerprint(
        "com.example",
        "17.17.0",
        command_runner=lambda args: values[tuple(args)],
    )
    text = result.model_dump_json()
    assert "SERIAL-SECRET" not in text
    assert result.device_id_hash
    assert result.api_level == 36
    assert result.app_version_name == "4.2.0"
    assert result.app_version_code == "42"
    assert result.fingerprint_id.startswith("FP-")
