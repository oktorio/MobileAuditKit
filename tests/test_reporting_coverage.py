from mobileauditkit.models import Severity
from mobileauditkit.reporting import _sarif_level


def test_sarif_level():
    assert _sarif_level(Severity.CRITICAL) == "error"
    assert _sarif_level(Severity.HIGH) == "error"
    assert _sarif_level(Severity.MEDIUM) == "warning"
    assert _sarif_level(Severity.LOW) == "note"
    assert _sarif_level(Severity.INFO) == "note"
