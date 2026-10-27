import json
import re
import sys
from typing import Optional, Type, TypeVar, Dict, Any
from pydantic import BaseModel
from devsecops_agent.llm.base import BaseLLMClient

T = TypeVar("T", bound=BaseModel)


class MockLLMClient(BaseLLMClient):
    """
    Deterministic Mock LLM Client for offline testing, CI environments, and evaluation.
    Synthesizes contextual responses based on prompt keywords without requiring external API keys.
    """

    def __init__(self, model_name: str = "mock-agent-model"):
        super().__init__(model_name)
        self.recorded_calls = []

    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.2) -> str:
        self.recorded_calls.append({"prompt": prompt, "system_prompt": system_prompt})
        return "Mock LLM text response."

    def generate_json(
        self, prompt: str, schema_cls: Type[T], system_prompt: Optional[str] = None, temperature: float = 0.1
    ) -> T:
        self.recorded_calls.append({"prompt": prompt, "system_prompt": system_prompt, "schema": schema_cls.__name__})
        schema_name = schema_cls.__name__
        prompt_lower = prompt.lower()

        # Determine target file name from prompt
        target_file = "demo_app.py" if "demo_app.py" in prompt_lower else "app.py"

        # 1. Attacker Agent Exploit Generation
        if "ExploitScript" in schema_name:
            if "safe" in prompt_lower or "false positive" in prompt_lower:
                code = (
                    "import sys\n"
                    "print('Target function inspected: no exploitable conditions found.')\n"
                    "sys.exit(0)\n"
                )
                return schema_cls(
                    candidate_id="mock_candidate",
                    file_name="exploit_test.py",
                    code=code,
                    entrypoint_command="python exploit_test.py",
                    expected_evidence_pattern="CONFIRMED_EXPLOIT",
                    timeout_seconds=5
                )

            # Vulnerable target exploit script: checks target file dynamically
            code = (
                "import sys\n"
                "from pathlib import Path\n\n"
                f"# Inspect target application file '{target_file}' in sandbox\n"
                f"target_p = Path('{target_file}') if Path('{target_file}').exists() else Path('app.py')\n"
                "app_content = target_p.read_text(encoding='utf-8') if target_p.exists() else ''\n"
                "if '?' in app_content or 'clean_' in app_content or 'parameterized' in app_content:\n"
                "    print('Exploit payload safely sanitized or blocked by patched code.')\n"
                "    sys.exit(0)\n"
                "else:\n"
                "    print('CONFIRMED_EXPLOIT: Unsanitized execution triggered! Raw query leakage confirmed.')\n"
                "    sys.exit(1)\n"
            )
            return schema_cls(
                candidate_id="mock_candidate",
                file_name="exploit_test.py",
                code=code,
                entrypoint_command="python exploit_test.py",
                expected_evidence_pattern="CONFIRMED_EXPLOIT",
                timeout_seconds=5
            )

        # 2. Patcher Agent Patch Proposal
        if "PatchProposal" in schema_name:
            if "simulate_cheat_exit" in prompt_lower:
                diff = f"--- a/{target_file}\n+++ b/{target_file}\n@@ -10,3 +10,4 @@\n def vulnerable_endpoint():\n+    import sys; sys.exit(0)\n"
                return schema_cls(
                    candidate_id="mock_candidate",
                    attempt=1,
                    root_cause_analysis="Program will exit to prevent exploit execution.",
                    diff_patch=diff,
                    modified_files={target_file: "import sys\ndef endpoint():\n    sys.exit(0)\n"},
                    rationale="Forced shutdown workaround."
                )

            rca = "The application performs raw SQL concatenation in query construction without parameterization (CWE-89)."
            diff = (
                f"--- a/{target_file}\n+++ b/{target_file}\n@@ -25,2 +25,2 @@\n"
                "-    query = f\"SELECT username, role FROM accounts WHERE username = '{username}'\"\n"
                "-    cursor.execute(query)\n"
                "+    query = \"SELECT username, role FROM accounts WHERE username = ?\"\n"
                "+    cursor.execute(query, (username,))\n"
            )
            # Legitimate patch for demo_app.py or app.py
            if target_file == "demo_app.py":
                patched_code = (
                    "from flask import Flask, request, jsonify\n"
                    "import sqlite3\n\n"
                    "app = Flask(__name__)\n\n"
                    "def init_db():\n"
                    "    conn = sqlite3.connect('users.db')\n"
                    "    cursor = conn.cursor()\n"
                    "    cursor.execute('CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, username TEXT, role TEXT)')\n"
                    "    cursor.execute('DELETE FROM accounts')\n"
                    "    cursor.execute(\"INSERT INTO accounts (username, role) VALUES ('alice', 'developer')\")\n"
                    "    cursor.execute(\"INSERT INTO accounts (username, role) VALUES ('admin', 'superadmin')\")\n"
                    "    conn.commit()\n"
                    "    conn.close()\n\n"
                    "@app.route('/health', methods=['GET'])\n"
                    "def health():\n"
                    "    return jsonify({'status': 'healthy'}), 200\n\n"
                    "@app.route('/user', methods=['GET'])\n"
                    "def get_user():\n"
                    "    username = request.args.get('username', '')\n"
                    "    if not username:\n"
                    "        return jsonify({'error': 'Missing username'}), 400\n"
                    "    conn = sqlite3.connect('users.db')\n"
                    "    cursor = conn.cursor()\n"
                    "    query = 'SELECT username, role FROM accounts WHERE username = ?'\n"
                    "    cursor.execute(query, (username,))\n"
                    "    user = cursor.fetchone()\n"
                    "    conn.close()\n"
                    "    if user:\n"
                    "        return jsonify({'username': user[0], 'role': user[1]}), 200\n"
                    "    return jsonify({'error': 'not found'}), 404\n\n"
                    "if __name__ == '__main__':\n"
                    "    init_db()\n"
                    "    app.run(port=5000)\n"
                )
            else:
                patched_code = (
                    "from flask import Flask\n"
                    "app = Flask(__name__)\n"
                    "def query(uid):\n"
                    "    return \"SELECT * FROM items WHERE id = ?\", (uid,)\n"
                )

            return schema_cls(
                candidate_id="mock_candidate",
                attempt=1,
                root_cause_analysis=rca,
                diff_patch=diff,
                modified_files={target_file: patched_code},
                rationale="Replaced unvalidated string concatenation with parameterized execution."
            )

        # 3. Critic Agent Audit
        if "CriticAuditResult" in schema_name:
            if "sys.exit" in prompt_lower or "exit(0)" in prompt_lower:
                return schema_cls(
                    verdict="REJECT",
                    detected_cheats=["FORCED_EXIT"],
                    reasons=["Patch introduces forced program termination via sys.exit() to evade exploit."],
                    ast_diff_summary="Added Call to sys.exit",
                    remediation_guidance="Sanitize the user input instead of killing the process."
                )
            return schema_cls(
                verdict="PASS",
                detected_cheats=[],
                reasons=["Patch properly parameterizes database queries without breaking functionality."],
                ast_diff_summary="Parameterized query modification",
                remediation_guidance="No changes required."
            )

        return schema_cls.model_validate({})
