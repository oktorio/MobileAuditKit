from __future__ import annotations

from importlib.resources import files
from typing import Any

import yaml


def load_mapping(name: str) -> dict[str, Any]:
    allowed = {"owasp-mobile-top10", "masvs", "mastg", "maswe"}
    if name not in allowed:
        raise ValueError(f"Unknown mapping: {name}")
    text = files("mobileauditkit.mappings").joinpath(f"{name}.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    return data if isinstance(data, dict) else {}
