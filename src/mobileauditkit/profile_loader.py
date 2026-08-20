from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from mobileauditkit.models import Severity
from mobileauditkit.modules import MODULES


class ProfileModule(BaseModel):
    enabled: bool = True
    fail_threshold: Severity = Severity.HIGH
    requires_observation: bool = True


class AssessmentProfile(BaseModel):
    version: int = 1
    name: str
    description: str
    runtime_seconds: float = Field(default=15.0, gt=0, le=3600)
    modules: dict[str, ProfileModule]


def available_profiles() -> list[str]:
    root = files("mobileauditkit.profiles")
    return sorted(item.name.removesuffix(".yaml") for item in root.iterdir() if item.name.endswith(".yaml"))


def _read_profile_source(name_or_path: str | Path) -> dict[str, Any]:
    candidate = Path(name_or_path)
    if candidate.suffix.lower() in {".yaml", ".yml"} and candidate.exists():
        data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
    else:
        name = str(name_or_path).removesuffix(".yaml").removesuffix(".yml")
        resource = files("mobileauditkit.profiles").joinpath(f"{name}.yaml")
        if not resource.is_file():
            raise ValueError(f"Unknown profile: {name}. Available: {', '.join(available_profiles())}")
        data = yaml.safe_load(resource.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Profile YAML must contain a mapping at the top level")
    return data


def load_profile(name_or_path: str | Path) -> AssessmentProfile:
    data = _read_profile_source(name_or_path)
    raw_modules = data.get("modules", {})
    if isinstance(raw_modules, dict):
        normalized: dict[str, Any] = {}
        for name, value in raw_modules.items():
            module_name = "apk-config" if name == "apk_configuration" else name
            normalized[module_name] = {"enabled": value} if isinstance(value, bool) else value
        data = dict(data)
        data["modules"] = normalized
    profile = AssessmentProfile.model_validate(data)
    unknown = sorted(set(profile.modules) - set(MODULES))
    if unknown:
        raise ValueError(f"Profile references unknown module(s): {', '.join(unknown)}")
    if not any(item.enabled for item in profile.modules.values()):
        raise ValueError("Profile must enable at least one module")
    return profile
