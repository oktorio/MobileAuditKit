from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    description: str
    agent_filename: str | None
    owasp: tuple[str, ...]
    masvs: tuple[str, ...]
    mastg: tuple[str, ...] = ()
    maswe: tuple[str, ...] = ()


MODULES: dict[str, ModuleSpec] = {
    "crypto": ModuleSpec("crypto", "Observe cryptographic algorithms and modes without capturing key material or data", "crypto.js", ("M10",), ("MASVS-CRYPTO-1", "MASVS-CRYPTO-2"), ("MASTG-TEST-0232",), ("MASWE-0007", "MASWE-0008")),
    "storage": ModuleSpec("storage", "Observe storage API usage and storage locations without dumping application data", "storage.js", ("M9",), ("MASVS-STORAGE-1", "MASVS-STORAGE-2"), ("MASTG-TEST-0201", "MASTG-TEST-0207", "MASTG-TEST-0287"), ("MASWE-0001", "MASWE-0002")),
    "network": ModuleSpec("network", "Observe cleartext URLs, TLS setup, hostname verification and pinning controls", "network.js", ("M5",), ("MASVS-NETWORK-1", "MASVS-NETWORK-2"), ("MASTG-TEST-0236", "MASTG-TEST-0282", "MASTG-TEST-0283"), ("MASWE-0050", "MASWE-0052", "MASWE-0047")),
    "authentication": ModuleSpec("authentication", "Observe biometric/platform authentication configuration without bypassing it", "authentication.js", ("M3",), ("MASVS-AUTH-1", "MASVS-AUTH-2", "MASVS-AUTH-3"), ("MASTG-TEST-0326", "MASTG-TEST-0327"), ("MASWE-0020",)),
    "webview": ModuleSpec("webview", "Observe security-relevant WebView settings and JavaScript interfaces", "webview.js", ("M4", "M8"), ("MASVS-PLATFORM-2",), ("MASTG-TEST-0251", "MASTG-TEST-0253", "MASTG-TEST-0334"), ("MASWE-0033", "MASWE-0034", "MASWE-0035")),
    "privacy": ModuleSpec("privacy", "Observe clipboard, logging, location and screenshot-protection APIs without content capture", "privacy.js", ("M6",), ("MASVS-PRIVACY-1", "MASVS-PLATFORM-1", "MASVS-STORAGE-2"), ("MASTG-TEST-0231", "MASTG-TEST-0291"), ("MASWE-0030", "MASWE-0005")),
    "resilience": ModuleSpec("resilience", "Observe root and debugging detection controls without disabling or bypassing them", "resilience.js", ("M7",), ("MASVS-RESILIENCE-1", "MASVS-RESILIENCE-4"), ("MASTG-TEST-0325", "MASTG-TEST-0353"), ("MASWE-0051", "MASWE-0064")),
    "apk-config": ModuleSpec(
        "apk-config",
        "Deep static APK analysis: manifest, network/backup resources, package content, signing, native, and dependency metadata",
        None,
        ("M2", "M4", "M5", "M6", "M7", "M8", "M9"),
        ("MASVS-CODE-1", "MASVS-CODE-3", "MASVS-NETWORK-1", "MASVS-STORAGE-1", "MASVS-STORAGE-2", "MASVS-PLATFORM-1", "MASVS-PRIVACY-1", "MASVS-RESILIENCE-2", "MASVS-RESILIENCE-4"),
        ("MASTG-TEST-0216", "MASTG-TEST-0235", "MASTG-TEST-0364", "MASTG-TEST-0365"),
        ("MASWE-0006", "MASWE-0042", "MASWE-0050", "MASWE-0067"),
    ),
}


def get_module(name: str) -> ModuleSpec:
    try:
        return MODULES[name]
    except KeyError as exc:
        raise ValueError(f"Unknown module: {name}") from exc


def agent_path(name: str) -> Path:
    spec = get_module(name)
    if spec.agent_filename is None:
        raise ValueError(f"Module {name} does not use a Frida agent")
    return Path(str(files("mobileauditkit.agents").joinpath(spec.agent_filename)))
