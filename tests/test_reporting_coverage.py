from mobileauditkit.reporting import assessment_to_sarif, _sarif_level
from mobileauditkit.models import AssessmentReport, CoverageSummary, Finding, Severity

def test_sarif_level():
    assert _sarif_level(Severity.CRITICAL) == "error"
    assert _sarif_level(Severity.HIGH) == "error"
    assert _sarif_level(Severity.MEDIUM) == "warning"
    assert _sarif_level(Severity.LOW) == "note"
    assert _sarif_level(Severity.INFO) == "note"
