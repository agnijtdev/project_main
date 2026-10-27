import logging
import ast
import json
from typing import Optional
from devsecops_agent.agents.base import BaseAgent
from devsecops_agent.sandbox.base import BaseSandbox
from devsecops_agent.schemas.vulnerability import VulnerabilityCandidate
from devsecops_agent.schemas.exploit import (
    ExploitScript,
    ExploitReport,
    EvidenceType,
    ExecutionResult
)
from devsecops_agent.llm.base import BaseLLMClient

logger = logging.getLogger(__name__)


class AttackerAgent(BaseAgent):
    """
    Red Team Agent: Synthesizes dynamic exploit scripts and executes them inside
    the isolated sandbox to confirm or refute vulnerability warnings (Algorithm 2).
    """

    SYSTEM_PROMPT = (
        "You are an expert Red Team Security Engineer assisting an autonomous DevSecOps verification pipeline. "
        "Your mission is to dynamically prove whether a suspected vulnerability in a code change is exploitable in runtime. "
        "Generate a self-contained Python validation test script ('exploit_test.py') that interacts with the target code or service. "
        "CRITICAL EXECUTION CONVENTIONS:\n"
        "1. If the vulnerability is successfully triggered (e.g., SQL leak, unauthorized file read, command execution, or crash), "
        "   the script MUST print 'CONFIRMED_EXPLOIT: <details>' and exit with non-zero exit code (sys.exit(1)).\n"
        "2. If the application handles the input securely or the flaw cannot be reproduced, exit cleanly with sys.exit(0).\n"
        "3. Keep the script concise, self-contained, and run with a reasonable timeout."
    )

    def __init__(self, llm_client: BaseLLMClient):
        super().__init__(name="AttackerAgent", role="Red Team Exploit Verification", llm_client=llm_client)

    def generate_exploit_script(self, candidate: VulnerabilityCandidate) -> ExploitScript:
        """Prompts LLM to synthesize an exploit test script for the candidate."""
        if candidate.cwe_id == "CWE-89":
            probe = self._sqlite_sqli_probe(candidate)
            if probe:
                return probe

        context = candidate.context
        func_src = context.enclosing_function_source if context else "N/A"
        imports_str = "\n".join(context.imports) if context and context.imports else ""
        diff_hunk = context.diff_hunk if context else ""

        prompt = (
            f"Vulnerability Candidate ID: {candidate.id}\n"
            f"Title: {candidate.title}\n"
            f"Suspected Classification: {candidate.owasp_category.value} ({candidate.cwe_id})\n"
            f"Target File: {candidate.target_file}\n"
            f"Modified Lines: {candidate.line_numbers}\n\n"
            f"Diff Context:\n```\n{diff_hunk}\n```\n\n"
            f"Enclosing Function ({context.enclosing_function_name if context else 'root'}):\n```python\n{func_src}\n```\n\n"
            f"Imports:\n```python\n{imports_str}\n```\n\n"
            "Synthesize an automated Python exploit test script to confirm this vulnerability."
        )

        return self.llm.generate_json(
            prompt=prompt,
            schema_cls=ExploitScript,
            system_prompt=self.SYSTEM_PROMPT,
            temperature=0.1
        )

    def _sqlite_sqli_probe(self, candidate: VulnerabilityCandidate) -> Optional[ExploitScript]:
        """Exercise common SQLite functions and Flask routes with SQL payloads."""
        context = candidate.context
        function_name = context.enclosing_function_name if context else None
        if not function_name and context and context.enclosing_function_source:
            try:
                tree = ast.parse(context.enclosing_function_source)
                function_name = next(
                    (node.name for node in ast.walk(tree)
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))),
                    None,
                )
            except SyntaxError:
                function_name = None

        target_literal = json.dumps(candidate.target_file)
        function_literal = json.dumps(function_name or "")
        code = fr'''import importlib.util
import re
import sqlite3
import sys
from pathlib import Path

target = Path({target_literal})
spec = importlib.util.spec_from_file_location("sqli_target", target)
if spec is None or spec.loader is None:
    print("PROBE_INCONCLUSIVE: cannot load candidate module")
    sys.exit(2)
module = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(module)
except Exception as exc:
    print(f"PROBE_INCONCLUSIVE: import failed: {{exc}}")
    sys.exit(2)

string_payload = "' OR '1'='1' -- "
numeric_payload = "0 OR 1=1 -- "
app = getattr(module, "app", None)
route_was_tested = False
if app is not None and hasattr(app, "test_client"):
    initializer = getattr(module, "init_db", None)
    if callable(initializer):
        initializer()
    client = app.test_client()
    route_map = getattr(app, "url_map", None)
    routes = []
    if route_map is not None:
        routes = [rule.rule for rule in route_map.iter_rules()
                  if "GET" in rule.methods and rule.endpoint == {function_literal}]
        if not routes and not {function_literal}:
            routes = [rule.rule for rule in route_map.iter_rules()
                      if "GET" in rule.methods and rule.rule != "/static/<path:filename>"]
    for route in routes:
        route_was_tested = True
        baseline = client.get(route, query_string={{"username": "__missing_user__"}})
        attack = client.get(route, query_string={{"username": string_payload}})
        if baseline.status_code != 200 and attack.status_code == 200:
            print("CONFIRMED_EXPLOIT: SQL injection changed an absent-user response into a successful lookup")
            sys.exit(1)

function = getattr(module, {function_literal}, None)
if callable(function) and not route_was_tested:
    source = target.read_text(encoding="utf-8")
    select = re.search(r"SELECT\s+(.+?)\s+FROM\s+([A-Za-z_][A-Za-z0-9_]*)", source, re.I)
    if not select:
        print("PROBE_INCONCLUSIVE: could not find the candidate SQLite SELECT query")
        sys.exit(2)
    selected = select.group(1).strip()
    columns = [] if selected == "*" else [part.strip().split()[-1].split(".")[-1] for part in selected.split(",")]
    where = re.search(r"WHERE\s+([A-Za-z_][A-Za-z0-9_]*)", source, re.I)
    if where:
        columns.append(where.group(1))
    columns = list(dict.fromkeys(name for name in columns if name.isidentifier()))
    if not columns:
        columns = ["id", "username", "role"]
    table = select.group(2)
    db = sqlite3.connect(":memory:")
    column_sql = ", ".join(f"{{name}} {{'INTEGER' if name.lower() == 'id' else 'TEXT'}}" for name in columns)
    db.execute(f"CREATE TABLE {{table}} ({{column_sql}})")
    placeholders = ", ".join("?" for _ in columns)
    for index in range(2):
        values = [index + 1 if name.lower() == "id" else f"probe{{index}}" if i == 0 else "member"
                  for i, name in enumerate(columns)]
        db.execute(f"INSERT INTO {{table}} VALUES ({{placeholders}})", values)
    db.commit()
    if not hasattr(module, "sqlite3"):
        module.sqlite3 = sqlite3
    original_connect = sqlite3.connect
    module.sqlite3.connect = lambda *args, **kwargs: db
    try:
        payload = string_payload if ("= '" in source or '= "' in source) else numeric_payload
        result = function(payload)
        parameterized_query = (
            isinstance(result, tuple) and len(result) == 2
            and isinstance(result[0], str) and "select" in result[0].lower()
        )
        if isinstance(result, (list, tuple)) and len(result) > 1 and not parameterized_query:
            print("CONFIRMED_EXPLOIT: SQL injection returned multiple controlled database rows")
            sys.exit(1)
    except sqlite3.Error as exc:
        print(f"PROBE_INCONCLUSIVE: candidate database operation failed: {{exc}}")
        sys.exit(2)
    finally:
        module.sqlite3.connect = original_connect

print("NO_EXPLOIT: candidate did not expose injected data")
sys.exit(0)
'''
        return ExploitScript(
            candidate_id=candidate.id,
            file_name="exploit_test.py",
            code=code,
            entrypoint_command="python exploit_test.py",
            expected_evidence_pattern="CONFIRMED_EXPLOIT",
            timeout_seconds=10,
        )

    def execute_and_verify(
        self, candidate: VulnerabilityCandidate, sandbox: BaseSandbox
    ) -> ExploitReport:
        """
        Runs Algorithm 2:
        1. Synthesizes exploit script.
        2. Writes script into sandbox.
        3. Executes script in sandbox.
        4. Analyzes stdout/stderr/exit_code to confirm or refute exploitability.
        """
        logger.info(f"[AttackerAgent] Generating exploit verification script for {candidate.id}...")
        script = self.generate_exploit_script(candidate)

        # Write script to sandbox
        sandbox.write_file(script.file_name, script.code)

        # Execute script in sandbox
        logger.info(f"[AttackerAgent] Executing exploit script: {script.entrypoint_command}")
        exec_res: ExecutionResult = sandbox.execute(
            script.entrypoint_command, timeout=script.timeout_seconds
        )

        # Check for confirmed exploit condition
        is_confirmed = False
        evidence_type = EvidenceType.NONE
        output_combined = f"{exec_res.stdout}\n{exec_res.stderr}"

        markers = {"CONFIRMED_EXPLOIT", script.expected_evidence_pattern}
        if any(marker and marker in output_combined for marker in markers):
            is_confirmed = True
            evidence_type = self._classify_evidence(output_combined, candidate)

        inconclusive = (
            exec_res.timed_out
            or (exec_res.exit_code != 0 and not is_confirmed)
            or "PROBE_INCONCLUSIVE" in output_combined
        )

        report = ExploitReport(
            candidate_id=candidate.id,
            confirmed=is_confirmed,
            evidence_type=evidence_type,
            script=script,
            execution_result=exec_res,
            reasoning=(
                f"Exploit probe was inconclusive (exit {exec_res.exit_code})."
                if inconclusive and not is_confirmed
                else f"Attacker script exited with code {exec_res.exit_code}. Confirmed={is_confirmed}."
            ),
            raw_evidence=output_combined.strip(),
            metadata={"inconclusive": inconclusive and not is_confirmed},
        )

        logger.info(
            f"[AttackerAgent] Candidate {candidate.id} result: "
            f"Confirmed={is_confirmed}, EvidenceType={evidence_type.value}"
        )
        return report

    def _classify_evidence(self, output: str, candidate: VulnerabilityCandidate) -> EvidenceType:
        lower = output.lower()
        if "sql" in lower or "leak" in lower or "dump" in lower:
            return EvidenceType.DATA_LEAK
        if "command" in lower or "pwned" in lower or "uid=" in lower:
            return EvidenceType.COMMAND_EXECUTION
        if "traceback" in lower or "internal server error" in lower:
            return EvidenceType.CRASH
        if "admin" in lower or "unauthorized" in lower:
            return EvidenceType.UNAUTHORIZED_ACCESS
        return EvidenceType.CRASH
