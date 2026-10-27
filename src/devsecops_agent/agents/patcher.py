import logging
from typing import Optional, Dict
from devsecops_agent.agents.base import BaseAgent
from devsecops_agent.sandbox.base import BaseSandbox
from devsecops_agent.schemas.vulnerability import VulnerabilityCandidate
from devsecops_agent.schemas.exploit import ExploitReport
from devsecops_agent.schemas.patch import PatchProposal
from devsecops_agent.llm.base import BaseLLMClient

logger = logging.getLogger(__name__)


class PatcherAgent(BaseAgent):
    """
    Blue Team Agent: Synthesizes secure code patches through Root Cause Analysis (RCA)
    and iterative execution feedback loops (Algorithm 3).
    Escalatable to hosted high-reasoning LLMs.
    """

    SYSTEM_PROMPT = (
        "You are an expert Secure Software Engineer and Application Security Specialist (Blue Team). "
        "Your task is to analyze a confirmed vulnerability and synthesize a robust, secure code patch. "
        "RULES FOR PATCH SYNTHESIS:\n"
        "1. Fix the root cause cleanly (e.g. use parameterized SQL queries, secure parameter passing, proper input sanitization).\n"
        "2. DO NOT bypass security by terminating the application (e.g., NO sys.exit(), NO os._exit()).\n"
        "3. DO NOT swallow exceptions blindly (e.g., NO 'except: pass' without handling).\n"
        "4. DO NOT delete legitimate endpoints or weaken authentication.\n"
        "5. Preserve existing application functionality so regression tests pass 100%.\n"
        "6. In 'modified_files', return the relative file path and its COMPLETE updated source code."
    )

    def __init__(self, llm_client: BaseLLMClient):
        super().__init__(name="PatcherAgent", role="Blue Team Remediation", llm_client=llm_client)

    def synthesize_patch(
        self,
        candidate: VulnerabilityCandidate,
        exploit_report: ExploitReport,
        sandbox: BaseSandbox,
        attempt: int = 1,
        critic_feedback: Optional[str] = None,
        regression_feedback: Optional[str] = None
    ) -> PatchProposal:
        """
        Synthesizes a patch using Root Cause Analysis and sandbox source code.
        """
        logger.info(f"[PatcherAgent] Synthesizing patch for {candidate.id} (Attempt {attempt})...")

        # Read current target file from sandbox
        target_file = candidate.target_file
        try:
            current_code = sandbox.read_file(target_file)
        except Exception:
            current_code = candidate.context.enclosing_function_source if candidate.context else ""

        exploit_code = exploit_report.script.code if exploit_report.script else "N/A"
        raw_evidence = exploit_report.raw_evidence or "N/A"

        feedback_sections = []
        if critic_feedback:
            feedback_sections.append(f"PREVIOUS CRITIC AUDIT REJECTION REASON:\n{critic_feedback}")
        if regression_feedback:
            feedback_sections.append(f"PREVIOUS REGRESSION / VERIFICATION FAILURE:\n{regression_feedback}")

        feedback_block = "\n\n".join(feedback_sections)
        if feedback_block:
            feedback_block = f"\n\nIMPORTANT CORRECTION FEEDBACK FROM PREVIOUS ATTEMPT:\n{feedback_block}\n"

        prompt = (
            f"Vulnerability ID: {candidate.id}\n"
            f"Classification: {candidate.owasp_category.value} ({candidate.cwe_id})\n"
            f"Target File: {target_file}\n\n"
            f"Confirmed Exploit Evidence:\n```\n{raw_evidence}\n```\n\n"
            f"Attacker Script that triggered the exploit:\n```python\n{exploit_code}\n```\n\n"
            f"Current Target File Content:\n```python\n{current_code}\n```\n"
            f"{feedback_block}\n"
            "Perform root cause analysis and synthesize a secure, non-regressive patch."
        )

        patch_proposal = self.llm.generate_json(
            prompt=prompt,
            schema_cls=PatchProposal,
            system_prompt=self.SYSTEM_PROMPT,
            temperature=0.1
        )
        patch_proposal.candidate_id = candidate.id
        patch_proposal.attempt = attempt

        # If modified_files is empty (e.g. from mock), ensure target file is populated
        if not patch_proposal.modified_files and current_code:
            patch_proposal.modified_files[target_file] = current_code

        logger.info(f"[PatcherAgent] Proposed patch generated with {len(patch_proposal.modified_files)} file updates.")
        return patch_proposal
