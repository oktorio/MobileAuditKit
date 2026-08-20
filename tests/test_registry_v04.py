from mobileauditkit.test_registry import get_test, load_registry, tests_for_module as module_tests


def test_registry_ids_are_unique_and_versioned() -> None:
    registry = load_registry()
    ids = [item.test_id for item in registry.tests]
    assert len(ids) == len(set(ids))
    assert registry.version.startswith("2026.08")
    assert registry.reviewed_at == "2026-08-20"


def test_registry_contains_static_and_dynamic_tests() -> None:
    assert get_test("MAK-AND-0007").masvs == ["MASVS-NETWORK-1"]
    assert module_tests("network", engine="dynamic")[0].test_id == "MAK-DYN-0103"
