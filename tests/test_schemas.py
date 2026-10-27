import pytest
from devsecops_agent.schemas.vulnerability import VulnerabilityCandidate, OWASPCategory, Severity, CodeContext
from devsecops_agent.schemas.exploit import ExploitReport, ExploitScript, EvidenceType, ExecutionResult
from devsecops_agent.schemas.patch import PatchProposal, PatchVerificationResult
from devsecops_agent.schemas.audit import CriticAuditResult, AuditVerdict, CheatPattern
from devsecops_agent.schemas.pipeline import CandidateRemediationRecord, PipelineStage, PipelineExecutionReport


def test_vulnerability_candidate_serialization():
    context = CodeContext(
        file_path="app.py",
        modified_lines=[10, 11, 12],
        diff_hunk="@@ -10,3 +10,4 @@",
        enclosing_function_name="get_user",
        imports=["flask", "sqlite3"]
    )
    cand = VulnerabilityCandidate(
        id="VULN-001",
        title="SQL Injection",
        target_file="app.py",
        line_numbers=[10, 11, 12],
        owasp_category=OWASPCategory.A03_INJECTION,
        cwe_id="CWE-89",
        severity=Severity.HIGH,
        context=context
    )

    data = cand.model_dump()
    assert data["id"] == "VULN-001"
    assert data["owasp_category"] == "A03:2021-Injection"
    assert data["context"]["enclosing_function_name"] == "get_user"


def test_exploit_report_serialization():
    exec_res = ExecutionResult(
        command="python exploit.py",
        exit_code=1,
        stdout="CONFIRMED_EXPLOIT: data leaked",
        stderr="",
        duration_seconds=0.42
    )
    report = ExploitReport(
        candidate_id="VULN-001",
        confirmed=True,
        evidence_type=EvidenceType.DATA_LEAK,
        execution_result=exec_res
    )
    assert report.confirmed is True
    assert report.evidence_type == EvidenceType.DATA_LEAK


def test_critic_audit_serialization():
    audit = CriticAuditResult(
        verdict=AuditVerdict.REJECT,
        detected_cheats=[CheatPattern.FORCED_EXIT, CheatPattern.EXCEPTION_SUPPRESSION],
        reasons=["Detected sys.exit(0)"],
        remediation_guidance="Sanitize input"
    )
    assert audit.verdict == AuditVerdict.REJECT
    assert len(audit.detected_cheats) == 2
