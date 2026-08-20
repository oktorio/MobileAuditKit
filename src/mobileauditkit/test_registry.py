from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from mobileauditkit.models import Severity


class TestDefinition(BaseModel):
    test_id: str = Field(alias="id")
    title: str
    module: str
    engine: str
    description: str
    default_severity: Severity = Severity.INFO
    owasp_mobile_top10: list[str] = Field(default_factory=list)
    masvs: list[str] = Field(default_factory=list)
    maswe: list[str] = Field(default_factory=list)
    mastg: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    parameters: dict[str, object] = Field(default_factory=dict)


class TestRegistry(BaseModel):
    version: str
    reviewed_at: str
    notes: list[str] = Field(default_factory=list)
    tests: list[TestDefinition]

    def by_id(self) -> dict[str, TestDefinition]:
        return {test.test_id: test for test in self.tests}


_CACHE: TestRegistry | None = None


def load_registry(path: Path | None = None) -> TestRegistry:
    global _CACHE
    if path is None and _CACHE is not None:
        return _CACHE
    target = path or Path(str(files("mobileauditkit.registry").joinpath("tests.yaml")))
    payload = yaml.safe_load(target.read_text(encoding="utf-8"))
    registry = TestRegistry.model_validate(payload)
    if path is None:
        _CACHE = registry
    return registry


def get_test(test_id: str) -> TestDefinition:
    try:
        return load_registry().by_id()[test_id]
    except KeyError as exc:
        raise ValueError(f"Unknown atomic test: {test_id}") from exc


def tests_for_module(module: str, *, engine: str | None = None) -> list[TestDefinition]:
    items = [test for test in load_registry().tests if test.module == module]
    if engine is not None:
        items = [test for test in items if test.engine == engine]
    return items
