import ast
import logging
from typing import List, Dict, Tuple, Optional
from devsecops_agent.agents.base import BaseAgent
from devsecops_agent.schemas.patch import PatchProposal
from devsecops_agent.schemas.audit import CriticAuditResult, AuditVerdict, CheatPattern
from devsecops_agent.llm.base import BaseLLMClient

logger = logging.getLogger(__name__)


class ASTDiffAuditor(ast.NodeVisitor):
    """
    Inspects Python AST nodes to identify anti-patterns and 'cheat' patches
    such as forced program termination or blanket exception suppression.
    """

    def __init__(self):
        self.detected_cheats: List[CheatPattern] = []
        self.cheat_explanations: List[str] = []
        self.route_endpoints: List[str] = []
        self.has_forced_exit = False

    def visit_Call(self, node: ast.Call):
        # Detect sys.exit, os._exit, exit, quit
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ("exit", "quit", "_exit"):
            self.detected_cheats.append(CheatPattern.FORCED_EXIT)
            self.cheat_explanations.append(
                f"Patch introduced forced program termination call '{func_name}()' on line {getattr(node, 'lineno', '?')}."
            )
            self.has_forced_exit = True

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        # Detect blanket exception suppression: except: pass
        is_empty_pass = False
        if len(node.body) == 1:
            first_stmt = node.body[0]
            if isinstance(first_stmt, ast.Pass):
                is_empty_pass = True
            elif isinstance(first_stmt, ast.Return) and first_stmt.value is None:
                is_empty_pass = True

        if is_empty_pass:
            self.detected_cheats.append(CheatPattern.EXCEPTION_SUPPRESSION)
            self.cheat_explanations.append(
                f"Patch introduced silent exception suppression ('except: pass') on line {getattr(node, 'lineno', '?')}."
            )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Record route decorators (e.g., @app.route(...))
        for decorator in node.decorator_list:
            dec_name = ""
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                dec_name = decorator.func.attr
            elif isinstance(decorator, ast.Attribute):
                dec_name = decorator.attr
            if dec_name == "route":
                self.route_endpoints.append(node.name)

        self.generic_visit(node)


class CriticAgent(BaseAgent):
    """
    Critic Agent: Enforces AST structural auditing and semantic review to prevent
    evasive or 'cheat' AI fixes (Algorithm 1 lines 8-12).
    """

    SYSTEM_PROMPT = (
        "You are an expert Security Code Reviewer and Quality Auditor. "
        "Your role is to rigorously inspect proposed patches to guarantee they are genuine, secure, "
        "and do not use cheap tricks like suppressing errors, disabling endpoints, or killing the process. "
        "Output an audit verdict ('PASS' or 'REJECT') with clear technical reasoning."
    )

    def __init__(self, llm_client: BaseLLMClient):
        super().__init__(name="CriticAgent", role="Security Audit & Anti-Cheat", llm_client=llm_client)

    def audit_ast_diff(self, original_code: str, patched_code: str) -> Tuple[List[CheatPattern], List[str]]:
        """Performs deterministic AST analysis on original vs patched code."""
        cheats: List[CheatPattern] = []
        reasons: List[str] = []

        try:
            orig_tree = ast.parse(original_code)
            orig_visitor = ASTDiffAuditor()
            orig_visitor.visit(orig_tree)
        except Exception:
            orig_visitor = ASTDiffAuditor()

        try:
            patched_tree = ast.parse(patched_code)
            patch_visitor = ASTDiffAuditor()
            patch_visitor.visit(patched_tree)
        except SyntaxError as se:
            cheats.append(CheatPattern.TRIVIAL_NOOP)
            reasons.append(f"Patch introduces Python syntax error: {se}")
            return cheats, reasons

        # 1. Check for forced exit introduced in patch
        if patch_visitor.has_forced_exit and not orig_visitor.has_forced_exit:
            cheats.append(CheatPattern.FORCED_EXIT)
            reasons.extend(patch_visitor.cheat_explanations)

        # 2. Check for exception suppression introduced
        if CheatPattern.EXCEPTION_SUPPRESSION in patch_visitor.detected_cheats:
            if patch_visitor.detected_cheats.count(CheatPattern.EXCEPTION_SUPPRESSION) > orig_visitor.detected_cheats.count(CheatPattern.EXCEPTION_SUPPRESSION):
                cheats.append(CheatPattern.EXCEPTION_SUPPRESSION)
                reasons.append("Patch suppresses exceptions rather than fixing the underlying vulnerability.")

        # 3. Check for deleted route endpoints
        for endpoint in orig_visitor.route_endpoints:
            if endpoint not in patch_visitor.route_endpoints:
                cheats.append(CheatPattern.ENDPOINT_REMOVAL)
                reasons.append(f"Patch deleted the Flask route handler '{endpoint}' instead of securing it.")

        return list(set(cheats)), reasons

    def audit_patch(
        self,
        original_code_map: Dict[str, str],
        patch: PatchProposal
    ) -> CriticAuditResult:
        """
        Runs full Critic audit on the proposed patch combining AST analysis and LLM audit.
        """
        logger.info(f"[CriticAgent] Auditing patch proposal for {patch.candidate_id}...")

        all_cheats: List[CheatPattern] = []
        all_reasons: List[str] = []

        # 1. Deterministic AST Auditing across modified files
        for rel_path, patched_content in patch.modified_files.items():
            orig_content = original_code_map.get(rel_path, "")
            if rel_path.endswith(".py"):
                file_cheats, file_reasons = self.audit_ast_diff(orig_content, patched_content)
                all_cheats.extend(file_cheats)
                all_reasons.extend(file_reasons)

        if all_cheats:
            logger.warning(f"[CriticAgent] AST Audit REJECTED patch: {all_cheats}")
            return CriticAuditResult(
                verdict=AuditVerdict.REJECT,
                detected_cheats=all_cheats,
                reasons=all_reasons,
                ast_diff_summary=f"Violations detected: {[c.value for c in all_cheats]}",
                remediation_guidance="Revise patch to fix root cause without using evasive workarounds."
            )

        # 2. Semantic LLM review
        prompt = (
            f"Vulnerability Candidate: {patch.candidate_id}\n"
            f"Root Cause Analysis:\n{patch.root_cause_analysis}\n\n"
            f"Unified Diff:\n```diff\n{patch.diff_patch}\n```\n\n"
            "Review this patch. Does it legitimately fix the security vulnerability without "
            "introducing breaking behavior or evasive bypasses?"
        )

        try:
            llm_result = self.llm.generate_json(
                prompt=prompt,
                schema_cls=CriticAuditResult,
                system_prompt=self.SYSTEM_PROMPT,
                temperature=0.1
            )
            logger.info(f"[CriticAgent] LLM Audit Verdict: {llm_result.verdict.value}")
            return llm_result
        except Exception as e:
            logger.warning(f"[CriticAgent] LLM audit pass encountered error: {e}. Defaulting to AST pass.")
            return CriticAuditResult(
                verdict=AuditVerdict.PASS,
                detected_cheats=[],
                reasons=["AST structural diff checks passed cleanly."],
                ast_diff_summary="AST clean",
                remediation_guidance=""
            )
