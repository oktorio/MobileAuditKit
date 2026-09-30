import pytest

from mobileauditkit.mapping_catalog import load_mapping


def test_load_mapping_success():
    data = load_mapping("owasp-mobile-top10")
    assert isinstance(data, dict)
    assert len(data) > 0

def test_load_mapping_invalid():
    with pytest.raises(ValueError, match="Unknown mapping: invalid-mapping"):
        load_mapping("invalid-mapping")

def test_load_mapping_empty(monkeypatch):
    class MockResource:
        def read_text(self, encoding):
            return "not_a_dict"

    class MockJoinPath:
        def joinpath(self, name):
            return MockResource()

    monkeypatch.setattr("mobileauditkit.mapping_catalog.files", lambda pkg: MockJoinPath())

    data = load_mapping("owasp-mobile-top10")
    assert data == {}
