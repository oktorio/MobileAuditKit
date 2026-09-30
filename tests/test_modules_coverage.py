import pytest

from mobileauditkit.modules import agent_path, get_module


def test_get_module_invalid():
    with pytest.raises(ValueError, match="Unknown module: invalid-module"):
        get_module("invalid-module")

def test_agent_path_static():
    with pytest.raises(ValueError, match="Module apk-config does not use a Frida agent"):
        agent_path("apk-config")
