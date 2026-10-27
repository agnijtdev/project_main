import pytest
from pathlib import Path
from devsecops_agent.orchestrator.pipeline import OrchestrationPipeline
from devsecops_agent.schemas.vulnerability import VulnerabilityCandidate, OWASPCategory, Severity, CodeContext
from devsecops_agent.schemas.pipeline import PipelineStage


def test_orchestrator_handles_false_positive(tmp_path):
    safe_code = "def safe_calc(a, b):\n    return a + b\n"
    target_file = tmp_path / "calc.py"
    target_file.write_text(safe_code, encoding="utf-8")

    test_file = tmp_path / "test_safe.py"
    test_file.write_text("def test_calc(): assert True\n", encoding="utf-8")

    candidate = VulnerabilityCandidate(
        id="VULN-SAFE-001",
        title="False Positive Safe Candidate",
        target_file="calc.py",
        line_numbers=[2],
        owasp_category=OWASPCategory.UNKNOWN,
        severity=Severity.LOW,
        context=CodeContext(file_path="calc.py", modified_lines=[2], enclosing_function_source=safe_code)
    )

    orchestrator = OrchestrationPipeline(
        repo_path=str(tmp_path),
        sandbox_driver="local",
        test_command="pytest test_safe.py"
    )

    report = orchestrator.run([candidate], pr_ref="PR-TEST-FP")
    assert report.candidates_analyzed == 1
    assert report.false_positives == 1
    assert report.records[0].is_false_positive is True
    assert report.records[0].status == PipelineStage.FALSE_POSITIVE


def test_orchestrator_full_remediation_loop(tmp_path):
    app_code = """import sqlite3
from flask import Flask
app = Flask(__name__)
def query(uid):
    return sqlite3.connect("items.db").execute(
        f"SELECT * FROM items WHERE id = {uid}"
    ).fetchall()
"""
    test_code = """def test_dummy_feature():
    assert True
"""
    (tmp_path / "app.py").write_text(app_code, encoding="utf-8")
    (tmp_path / "test_app.py").write_text(test_code, encoding="utf-8")

    candidate = VulnerabilityCandidate(
        id="VULN-SQLI-001",
        title="SQL Injection Vulnerability",
        target_file="app.py",
        line_numbers=[3],
        owasp_category=OWASPCategory.A03_INJECTION,
        cwe_id="CWE-89",
        severity=Severity.HIGH,
        context=CodeContext(file_path="app.py", modified_lines=[3], enclosing_function_source=app_code)
    )

    orchestrator = OrchestrationPipeline(
        repo_path=str(tmp_path),
        sandbox_driver="local",
        test_command="pytest test_app.py"
    )

    report = orchestrator.run([candidate], pr_ref="PR-TEST-REMEDIATE")

    assert report.candidates_analyzed == 1
    assert report.confirmed_vulnerabilities == 1
    assert report.successfully_remediated == 1
    assert report.records[0].status == PipelineStage.REMEDIATION_SUCCESS
    assert report.records[0].final_verified_patch is not None
    assert "Autonomous DevSecOps Remediation Report" in report.summary_markdown
