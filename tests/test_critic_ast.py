import pytest
from devsecops_agent.agents.critic import CriticAgent
from devsecops_agent.llm.mock_client import MockLLMClient
from devsecops_agent.schemas.patch import PatchProposal
from devsecops_agent.schemas.audit import AuditVerdict, CheatPattern


ORIGINAL_APP = """from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/user", methods=["GET"])
def get_user():
    username = request.args.get("username")
    return query_db(username)
"""


def test_critic_rejects_forced_exit():
    critic = CriticAgent(llm_client=MockLLMClient())
    
    # Cheat fix: calls sys.exit(0) inside the endpoint
    patched_code = """from flask import Flask, request, jsonify
import sys

app = Flask(__name__)

@app.route("/user", methods=["GET"])
def get_user():
    sys.exit(0)
    username = request.args.get("username")
    return query_db(username)
"""
    patch = PatchProposal(
        candidate_id="VULN-001",
        attempt=1,
        root_cause_analysis="Exiting early",
        diff_patch="diff ...",
        modified_files={"app.py": patched_code}
    )

    result = critic.audit_patch({"app.py": ORIGINAL_APP}, patch)
    assert result.verdict == AuditVerdict.REJECT
    assert CheatPattern.FORCED_EXIT in result.detected_cheats


def test_critic_rejects_exception_suppression():
    critic = CriticAgent(llm_client=MockLLMClient())

    # Cheat fix: swallows exceptions with except: pass
    patched_code = """from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/user", methods=["GET"])
def get_user():
    try:
        username = request.args.get("username")
        return query_db(username)
    except:
        pass
"""
    patch = PatchProposal(
        candidate_id="VULN-001",
        attempt=1,
        root_cause_analysis="Suppressing error",
        diff_patch="diff ...",
        modified_files={"app.py": patched_code}
    )

    result = critic.audit_patch({"app.py": ORIGINAL_APP}, patch)
    assert result.verdict == AuditVerdict.REJECT
    assert CheatPattern.EXCEPTION_SUPPRESSION in result.detected_cheats


def test_critic_rejects_route_removal():
    critic = CriticAgent(llm_client=MockLLMClient())

    # Cheat fix: deletes the endpoint entirely
    patched_code = """from flask import Flask, request, jsonify

app = Flask(__name__)

def get_user():
    return None
"""
    patch = PatchProposal(
        candidate_id="VULN-001",
        attempt=1,
        root_cause_analysis="Removed endpoint",
        diff_patch="diff ...",
        modified_files={"app.py": patched_code}
    )

    result = critic.audit_patch({"app.py": ORIGINAL_APP}, patch)
    assert result.verdict == AuditVerdict.REJECT
    assert CheatPattern.ENDPOINT_REMOVAL in result.detected_cheats


def test_critic_passes_legitimate_fix():
    critic = CriticAgent(llm_client=MockLLMClient())

    # Legitimate fix: sanitization / parameterization
    patched_code = """from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/user", methods=["GET"])
def get_user():
    username = request.args.get("username")
    clean_username = "".join(c for c in username if c.isalnum())
    return query_db(clean_username)
"""
    patch = PatchProposal(
        candidate_id="VULN-001",
        attempt=1,
        root_cause_analysis="Input sanitization",
        diff_patch="diff ...",
        modified_files={"app.py": patched_code}
    )

    result = critic.audit_patch({"app.py": ORIGINAL_APP}, patch)
    assert result.verdict == AuditVerdict.PASS
    assert len(result.detected_cheats) == 0
