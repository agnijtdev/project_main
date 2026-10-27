import asyncio
import datetime
import logging
from typing import List, Optional, Dict
from pathlib import Path

from devsecops_agent.config import settings
from devsecops_agent.schemas.vulnerability import VulnerabilityCandidate
from devsecops_agent.schemas.exploit import ExploitReport, ExecutionResult
from devsecops_agent.schemas.patch import PatchProposal, PatchVerificationResult
from devsecops_agent.schemas.audit import CriticAuditResult, AuditVerdict
from devsecops_agent.schemas.pipeline import (
    PipelineStage,
    CandidateRemediationRecord,
    PipelineExecutionReport
)
from devsecops_agent.sandbox import BaseSandbox, create_sandbox
from devsecops_agent.agents.attacker import AttackerAgent
from devsecops_agent.agents.patcher import PatcherAgent
from devsecops_agent.agents.critic import CriticAgent
from devsecops_agent.llm.client import get_llm_client

logger = logging.getLogger(__name__)


class OrchestrationPipeline:
    """
    Orchestrator implementing Algorithms 1, 2, and 3:
    Coordinates Red Team (Attacker), Blue Team (Patcher), Critic (Auditor),
    and Dynamic Sandbox to achieve autonomous self-healing PR remediation.
    """

    def __init__(
        self,
        repo_path: str,
        sandbox_driver: Optional[str] = None,
        max_attempts: Optional[int] = None,
        test_command: str = "pytest"
    ):
        self.repo_path = repo_path
        self.sandbox_driver = sandbox_driver or settings.SANDBOX_DRIVER
        self.max_attempts = max_attempts or settings.MAX_PATCH_ATTEMPTS
        self.test_command = test_command

        # Initialize Agents with role-tailored LLM backends
        self.attacker = AttackerAgent(llm_client=get_llm_client(role="attacker"))
        self.patcher = PatcherAgent(llm_client=get_llm_client(role="patcher"))
        self.critic = CriticAgent(llm_client=get_llm_client(role="critic"))

    def run(
        self,
        candidates: List[VulnerabilityCandidate],
        pr_ref: str = "PR-HEAD"
    ) -> PipelineExecutionReport:
        """
        Executes Algorithm 1 loop across all vulnerability candidates extracted from PR.
        """
        start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        records: List[CandidateRemediationRecord] = []

        confirmed_count = 0
        false_positive_count = 0
        remediated_count = 0

        logger.info(f"Starting DevSecOps Orchestration Pipeline for PR ref '{pr_ref}' with {len(candidates)} candidate(s).")

        for candidate in candidates:
            record = self._remediate_candidate(candidate)
            records.append(record)

            if record.is_false_positive:
                false_positive_count += 1
            elif record.exploit_report and record.exploit_report.confirmed:
                confirmed_count += 1
                if record.status == PipelineStage.REMEDIATION_SUCCESS:
                    remediated_count += 1

        end_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

        report = PipelineExecutionReport(
            pull_request_ref=pr_ref,
            target_repo_path=self.repo_path,
            stage=PipelineStage.REMEDIATION_SUCCESS if remediated_count == confirmed_count else PipelineStage.AUDIT_COMPLETED,
            candidates_analyzed=len(candidates),
            confirmed_vulnerabilities=confirmed_count,
            false_positives=false_positive_count,
            successfully_remediated=remediated_count,
            records=records,
            start_time=start_time,
            end_time=end_time
        )

        report.summary_markdown = self._generate_markdown_report(report)
        return report

    async def run_async(
        self,
        candidates: List[VulnerabilityCandidate],
        pr_ref: str = "PR-HEAD"
    ) -> PipelineExecutionReport:
        """Asynchronous wrapper for async event loops / ASGI server integrations."""
        return await asyncio.to_thread(self.run, candidates, pr_ref)

    def _remediate_candidate(self, candidate: VulnerabilityCandidate) -> CandidateRemediationRecord:
        """Processes a single candidate through Algorithm 1."""
        record = CandidateRemediationRecord(candidate=candidate)

        # 1. Spin Up Sandbox S
        sandbox: BaseSandbox = create_sandbox(
            workspace_path=self.repo_path,
            driver=self.sandbox_driver
        )

        try:
            sandbox.start()
            record.status = PipelineStage.SANDBOX_INITIALIZED

            # Snapshot original code files
            original_code_map: Dict[str, str] = {}
            try:
                original_code_map[candidate.target_file] = sandbox.read_file(candidate.target_file)
            except Exception:
                pass

            # 2. Attacker Agent Exploit Confirmation (Algorithm 2)
            logger.info(f"--- [Algorithm 2] Exploit Confirmation: {candidate.id} ---")
            exploit_report: ExploitReport = self.attacker.execute_and_verify(candidate, sandbox)
            record.exploit_report = exploit_report
            record.status = PipelineStage.EXPLOITATION_ATTEMPTED

            if not exploit_report.confirmed:
                if exploit_report.metadata.get("inconclusive"):
                    logger.warning(
                        "Candidate %s could not be classified because its exploit probe failed: %s",
                        candidate.id,
                        exploit_report.raw_evidence,
                    )
                    record.status = PipelineStage.FAILED_REMEDIATION
                    return record
                # Algorithm 1 line 17: MarkAsFalsePositive(P)
                logger.info(f"Candidate {candidate.id} could not be exploited. Flagged as FALSE POSITIVE.")
                record.is_false_positive = True
                record.status = PipelineStage.FALSE_POSITIVE
                return record

            logger.info(f"Vulnerability {candidate.id} CONFIRMED! Threat type: {exploit_report.evidence_type.value}")

            # 3. Closed-Loop Remediation & Verification (Algorithm 3)
            critic_feedback: Optional[str] = None
            regression_feedback: Optional[str] = None

            for attempt in range(1, self.max_attempts + 1):
                logger.info(f"--- [Algorithm 3] Remediation Attempt {attempt}/{self.max_attempts} for {candidate.id} ---")

                # Synthesize patch (escalates to hosted model if needed)
                escalate_model = attempt > 1
                if escalate_model:
                    self.patcher.llm = get_llm_client(role="patcher", escalate=True)

                patch_proposal: PatchProposal = self.patcher.synthesize_patch(
                    candidate,
                    exploit_report,
                    sandbox,
                    attempt,
                    critic_feedback,
                    regression_feedback
                )
                record.patch_history.append(patch_proposal)

                # Critic Agent AST & anti-cheat audit
                critic_result: CriticAuditResult = self.critic.audit_patch(
                    original_code_map,
                    patch_proposal
                )
                record.critic_audit = critic_result

                if critic_result.verdict == AuditVerdict.REJECT:
                    logger.warning(f"[Critic REJECT] Attempt {attempt}: {critic_result.reasons}")
                    critic_feedback = "; ".join(critic_result.reasons)
                    continue  # Loop back to patcher with critic feedback

                # Apply patch to sandbox
                sandbox.apply_patch(patch_proposal.modified_files)

                # Verify Exploit is now BLOCKED (must fail)
                exploit_retest_cmd = (
                    exploit_report.script.entrypoint_command
                    if exploit_report.script
                    else "python exploit_test.py"
                )
                exploit_retest_res: ExecutionResult = sandbox.execute(exploit_retest_cmd)
                exploit_is_blocked = (
                    exploit_retest_res.exit_code == 0
                    and "CONFIRMED_EXPLOIT" not in exploit_retest_res.stdout
                )

                # Run Application Regression Feature Suite (must pass 100%)
                regression_res: ExecutionResult = sandbox.execute(self.test_command)
                regression_passed = regression_res.exit_code == 0

                verification = PatchVerificationResult(
                    candidate_id=candidate.id,
                    attempt=attempt,
                    patch_applied=True,
                    exploit_blocked=exploit_is_blocked,
                    regression_passed=regression_passed,
                    exploit_run_result=exploit_retest_res,
                    regression_run_result=regression_res,
                    summary=f"Exploit Blocked: {exploit_is_blocked}, Regression Suite Passed: {regression_passed}"
                )
                record.verification_history.append(verification)

                if exploit_is_blocked and regression_passed:
                    logger.info(f"VERIFIED SUCCESS for {candidate.id} on attempt {attempt}!")
                    record.status = PipelineStage.REMEDIATION_SUCCESS
                    record.final_verified_patch = patch_proposal
                    return record
                else:
                    failure_reasons = []
                    if not exploit_is_blocked:
                        failure_reasons.append(f"Exploit still succeeded (exit {exploit_retest_res.exit_code})")
                    if not regression_passed:
                        failure_reasons.append(f"Regression tests failed: {regression_res.stderr or regression_res.stdout}")
                    regression_feedback = " & ".join(failure_reasons)
                    logger.warning(f"Verification failed on attempt {attempt}: {regression_feedback}. Resetting sandbox.")
                    sandbox.reset()

            # If all attempts exhausted
            record.status = PipelineStage.FAILED_REMEDIATION
            return record

        finally:
            sandbox.stop()

    def _generate_markdown_report(self, report: PipelineExecutionReport) -> str:
        """Generates comprehensive PR comment / report in markdown."""
        lines = [
            "# Autonomous DevSecOps Remediation Report",
            "",
            f"**PR Reference:** `{report.pull_request_ref}`  ",
            f"**Execution Timestamp:** `{report.start_time}`  ",
            f"**Overall Status:** `{report.stage.value}`  ",
            "",
            "## Summary Metrics",
            f"- **Candidates Analyzed:** {report.candidates_analyzed}",
            f"- **Confirmed Vulnerabilities:** {report.confirmed_vulnerabilities}",
            f"- **False Positives Filtered:** {report.false_positives}",
            f"- **Successfully Remediated:** {report.successfully_remediated}",
            "",
            "---",
            "## Candidate Details"
        ]

        for rec in report.records:
            cand = rec.candidate
            lines.append(f"### Candidate: `{cand.id}` - {cand.title}")
            lines.append(f"- **OWASP Category:** `{cand.owasp_category.value}` ({cand.cwe_id})")
            lines.append(f"- **Target File:** `{cand.target_file}` (Lines {cand.line_numbers})")
            lines.append(f"- **Final Status:** **{rec.status.value}**")

            if rec.exploit_report:
                lines.append(f"- **Exploit Probe:** {rec.exploit_report.reasoning}")
                if rec.exploit_report.raw_evidence:
                    lines.extend(["```text", rec.exploit_report.raw_evidence[:2000], "```"])

            if rec.is_false_positive:
                lines.append("> [!NOTE] Dynamic exploit execution failed to reproduce an exploit or crash. Safely marked as false positive.")
            elif rec.exploit_report and rec.exploit_report.metadata.get("inconclusive"):
                lines.append("> [!WARNING] Exploit verification was inconclusive. The candidate is not classified as a false positive.")
            elif rec.final_verified_patch:
                lines.append("> [!IMPORTANT] Vulnerability confirmed, remediated, and verified non-regressive!")
                lines.append(f"**Root Cause Analysis:** {rec.final_verified_patch.root_cause_analysis}")
                lines.append("```diff")
                lines.append(rec.final_verified_patch.diff_patch.strip())
                lines.append("```")

            lines.append("")

        return "\n".join(lines)
