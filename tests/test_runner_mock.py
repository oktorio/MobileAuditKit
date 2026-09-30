from unittest.mock import MagicMock
from mobileauditkit.runner import run_observer
import pytest

def test_run_observer_success(monkeypatch):
    mock_frida = MagicMock()
    mock_device = MagicMock()
    mock_session = MagicMock()
    mock_script = MagicMock()

    mock_frida.get_usb_device.return_value = mock_device
    mock_device.attach.return_value = mock_session
    mock_session.create_script.return_value = mock_script

    import sys
    sys.modules['frida'] = mock_frida

    events_to_emit = []

    def on_message_handler(message_type, handler):
        def trigger():
            for msg, data in events_to_emit:
                handler(msg, data)
        mock_script.load.side_effect = trigger

    mock_script.on.side_effect = on_message_handler

    # Test valid message
    events_to_emit = [({"type": "send", "payload": {"event": "crypto_algorithm", "algorithm": "MD5"}}, None)]
    events = run_observer("com.example", "crypto", seconds=0.1)
    assert len(events) == 1
    assert events[0]["event"] == "crypto_algorithm"

    # Test error message
    events_to_emit = [({"type": "error", "description": "Frida error"}, None)]
    events = run_observer("com.example", "crypto", seconds=0.1)
    assert len(events) == 1
    assert events[0]["event"] == "agent_error"

    # Test spawn
    mock_device.spawn.return_value = 1234
    events_to_emit = []
    events = run_observer("com.example", "crypto", seconds=0.1, spawn=True)
    assert mock_device.spawn.called
    assert mock_device.resume.called

    del sys.modules['frida']

def test_run_observer_invalid_seconds():
    with pytest.raises(ValueError, match="seconds must be greater than zero"):
        run_observer("com.example", "crypto", seconds=0)
