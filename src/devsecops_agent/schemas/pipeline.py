from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from devsecops_agent.schemas.vulnerability import VulnerabilityCandidate, OWASPCategory
from devsecops_agent.schemas.exploit import ExploitReport
from devsecops_agent.schemas.patch import PatchProposal, PatchVerificationResult
from devsecops_agent.schemas.audit import CriticAuditResult


class PipelineStage(str, Enum):
    INITIALIZED = "INITIALIZED"
    CONTEXT_EXTRACTED = "CONTEXT_EXTRACTED"
    SANDBOX_INITIALIZED = "SANDBOX_INITIALIZED"
    EXPLOITATION_ATTEMPTED = "EXPLOITATION_ATTEMPTED"
    PATCH_SYNTHESIZED = "PATCH_SYNTHESIZED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    AUDIT_COMPLETED = "AUDIT_COMPLETED"
    REMEDIATION_SUCCESS = "REMEDIATION_SUCCESS"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FAILED_REMEDIATION = "FAILED_REMEDIATION"


class CandidateRemediationRecord(BaseModel):
    """Lifecycle record for a single vulnerability candidate in the PR."""
    candidate: VulnerabilityCandidate
    status: PipelineStage = PipelineStage.INITIALIZED
    is_false_positive: bool = False
    exploit_report: Optional[ExploitReport] = None
    patch_history: List[PatchProposal] = Field(default_factory=list)
    verification_history: List[PatchVerificationResult] = Field(default_factory=list)
    critic_audit: Optional[CriticAuditResult] = None
    final_verified_patch: Optional[PatchProposal] = None


class PipelineExecutionReport(BaseModel):
    """Complete summary report of the Orchestration run for a Pull Request."""
    pull_request_ref: str
    target_repo_path: str
    stage: PipelineStage
    candidates_analyzed: int = 0
    confirmed_vulnerabilities: int = 0
    false_positives: int = 0
    successfully_remediated: int = 0
    records: List[CandidateRemediationRecord] = Field(default_factory=list)
    summary_markdown: str = ""
    start_time: str = ""
    end_time: str = ""
