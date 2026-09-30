import pytest
from mobileauditkit.profile_loader import load_profile, _read_profile_source
from pathlib import Path

def test_load_profile_unknown_module(tmp_path):
    p = tmp_path / "unknown_mod.yaml"
    p.write_text("""
name: "unknown_mod"
description: "test"
modules:
  invalid-mod: true
""")
    with pytest.raises(ValueError, match="Profile references unknown module"):
        load_profile(p)

def test_read_profile_source_not_dict(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("not_a_dict")
    with pytest.raises(ValueError, match="Profile YAML must contain a mapping"):
        _read_profile_source(p)

def test_load_profile_no_enabled_modules(tmp_path):
    p = tmp_path / "no_enabled.yaml"
    p.write_text("""
name: "no_enabled"
description: "test"
modules:
  crypto: false
""")
    with pytest.raises(ValueError, match="Profile must enable at least one module"):
        load_profile(p)
