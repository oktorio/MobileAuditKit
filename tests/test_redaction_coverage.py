from mobileauditkit.redaction import redact


def test_redact_recursive():
    # Test nested dict
    data = {"secret_level_1": {"token": "my-secret"}, "normal": "ok"}
    result = redact(data)
    assert result["secret_level_1"]["token"] == "[REDACTED]"

    # Test list
    data = ["bearer abcdefghijklmnopqrstuvwxyz123456", "normal"]
    result = redact(data)
    assert result[0] == "bearer [REDACTED_TOKEN]"

    # Test tuple
    data = ("bearer abcdefghijklmnopqrstuvwxyz123456", "normal")
    result = redact(data)
    assert result[0] == "bearer [REDACTED_TOKEN]"

    # Test other
    data = 123
    result = redact(data)
    assert result == 123
