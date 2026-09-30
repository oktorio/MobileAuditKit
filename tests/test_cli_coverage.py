
from typer.testing import CliRunner

from mobileauditkit.cli import app

runner = CliRunner()

def test_events_to_report(tmp_path):
    events_file = tmp_path / "events.jsonl"
    events_file.write_text('{"event": "crypto_algorithm", "algorithm": "MD5"}\n')

    json_out = tmp_path / "out.json"
    html_out = tmp_path / "out.html"

    # Missing args
    result = runner.invoke(app, ["events-to-report", "crypto", str(events_file)])
    assert result.exit_code == 0
    assert "MAK-CRYP" in result.stdout

    # With args
    result = runner.invoke(app, ["events-to-report", "crypto", str(events_file), "--output-json", str(json_out), "--output-html", str(html_out), "--package", "com.test"])
    assert result.exit_code == 0
    assert json_out.exists()
    assert html_out.exists()

def test_run_module(tmp_path):
    json_out = tmp_path / "out.json"
    html_out = tmp_path / "out.html"

    # mock run_observer
    def mock_run_observer(package, module, seconds, spawn):
        return [{"event": "crypto_algorithm", "algorithm": "MD5"}]

    import mobileauditkit.cli
    original = mobileauditkit.cli.run_observer
    mobileauditkit.cli.run_observer = mock_run_observer

    result = runner.invoke(app, ["run", "--package", "com.test", "--module", "crypto", "--json-report", str(json_out), "--html-report", str(html_out)])
    assert result.exit_code == 0
    assert json_out.exists()
    assert html_out.exists()

    mobileauditkit.cli.run_observer = original

def test_run_module_static():
    result = runner.invoke(app, ["run", "--package", "com.test", "--module", "apk-config"])
    assert result.exit_code != 0

def test_scan_assessment_invalid():
    result = runner.invoke(app, ["scan"])
    assert result.exit_code != 0


def test_scan_assessment(tmp_path):
    json_out = tmp_path / "out.json"
    html_out = tmp_path / "out.html"
    sarif_out = tmp_path / "out.sarif"

    def mock_run_assessment(*args, **kwargs):
        from datetime import UTC, datetime

        from mobileauditkit.models import AssessmentReport, CoverageSummary
        return AssessmentReport(
            assessment_id="test",
            tool_version="1",
            profile="test",
            profile_description="test",
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            modules=[],
            coverage=CoverageSummary(total_modules=0, pass_count=0, fail_count=0, inconclusive_count=0, not_tested_count=0, execution_coverage_percent=0.0, conclusive_coverage_percent=0.0),
            findings=[]
        )

    import mobileauditkit.cli
    original = mobileauditkit.cli.run_assessment
    mobileauditkit.cli.run_assessment = mock_run_assessment

    result = runner.invoke(app, ["scan", "--package", "com.test", "--json-report", str(json_out), "--html-report", str(html_out), "--sarif-report", str(sarif_out)])
    assert result.exit_code == 0
    assert json_out.exists()
    assert html_out.exists()
    assert sarif_out.exists()

    mobileauditkit.cli.run_assessment = original

def test_inspect_apk(tmp_path):
    apk = tmp_path / "test.apk"
    apk.write_text("test")

    json_out = tmp_path / "out.json"
    html_out = tmp_path / "out.html"

    def mock_inspect_apk_detailed(*args, **kwargs):
        from mobileauditkit.models import StaticAnalysisResult
        return StaticAnalysisResult()

    import mobileauditkit.cli
    original = mobileauditkit.cli.inspect_apk_detailed
    mobileauditkit.cli.inspect_apk_detailed = mock_inspect_apk_detailed

    result = runner.invoke(app, ["inspect-apk", str(apk), "--json-report", str(json_out), "--html-report", str(html_out)])
    assert result.exit_code == 0
    assert json_out.exists()
    assert html_out.exists()

    mobileauditkit.cli.inspect_apk_detailed = original
