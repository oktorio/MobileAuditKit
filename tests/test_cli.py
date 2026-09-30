from typer.testing import CliRunner
from mobileauditkit.cli import app

runner = CliRunner()

def test_doctor():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "MobileAuditKit doctor" in result.stdout.replace("\n", "")

def test_modules():
    result = runner.invoke(app, ["modules"])
    assert result.exit_code == 0
    assert "Assessment modules" in result.stdout.replace("\n", "")

def test_tests():
    result = runner.invoke(app, ["tests"])
    assert result.exit_code == 0
    assert "Atomic test registry" in result.stdout.replace("\n", "")

def test_profiles():
    result = runner.invoke(app, ["profiles"])
    assert result.exit_code == 0
    assert "Assessment profiles" in result.stdout.replace("\n", "")

def test_mappings():
    result = runner.invoke(app, ["mappings", "masvs"])
    assert result.exit_code == 0

def test_redact():
    result = runner.invoke(app, ["redact", "Bearer abcdefghijklmnopqrstuvwxyz123456"])
    assert result.exit_code == 0
    assert "[REDACTED_TOKEN]" in result.stdout.replace("\n", "")

def test_agent():
    result = runner.invoke(app, ["agent", "crypto"])
    assert result.exit_code == 0
    assert "crypto.js" in result.stdout.replace("\n", "")
