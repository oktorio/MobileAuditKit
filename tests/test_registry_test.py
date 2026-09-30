import pytest
from pydantic import ValidationError

import mobileauditkit.test_registry as tr


def test_load_registry_invalid(monkeypatch):
    class MockPath:
        def read_text(self, encoding):
            return ""

    def mock_safe_load(*args, **kwargs):
        return "not_a_dict"

    import yaml
    monkeypatch.setattr(yaml, "safe_load", mock_safe_load)

    with pytest.raises(ValidationError):
        tr.load_registry(path=MockPath())

def test_get_test_invalid():
    with pytest.raises(ValueError, match="Unknown atomic test: invalid"):
        tr.get_test("invalid")

def test_tests_for_module_func():
    tests = tr.tests_for_module("apk-config", engine="static")
    assert len(tests) > 0
