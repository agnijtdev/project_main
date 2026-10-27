import shutil
from pathlib import Path
from types import SimpleNamespace

from devsecops_agent.cli import _create_remediation_branch
from devsecops_agent.schemas.patch import PatchProposal
from devsecops_agent.schemas.pipeline import PipelineStage


def test_verified_patch_creates_separate_committed_branch(tmp_path, monkeypatch):
    repo = tmp_path / "project"
    repo.mkdir()
    original = "query = f'SELECT {value}'\n"
    (repo / "app.py").write_text(original, encoding="utf-8")
    patched = 'query = "SELECT * FROM users WHERE name = ?"\n'
    proposal = PatchProposal(
        candidate_id="VULN-PR-001",
        root_cause_analysis="Interpolated user input",
        diff_patch="parameterize query",
        modified_files={"app.py": patched},
    )
    record = SimpleNamespace(status=PipelineStage.REMEDIATION_SUCCESS, final_verified_patch=proposal)
    calls = []

    def fake_git(args, cwd, capture_output=True, text=True, check=False):
        calls.append(args)
        if args[1] == "show-ref":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if args[1] == "worktree":
            shutil.copytree(repo, Path(args[5]), dirs_exist_ok=True)
        if args[1] == "status":
            return SimpleNamespace(returncode=0, stdout=" M app.py\n", stderr="")
        if args[1] == "config":
            return SimpleNamespace(returncode=0, stdout="Test User\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("devsecops_agent.cli.subprocess.run", fake_git)
    branch, worktree = _create_remediation_branch(repo, "feature/demo", [record])

    assert branch.startswith("vulnerability/remediation-feature-demo-")
    assert (worktree / "app.py").read_text(encoding="utf-8") == patched
    assert (repo / "app.py").read_text(encoding="utf-8") == original
    assert any(args[1] == "commit" for args in calls)
    assert not any(args[1] == "checkout" for args in calls)
    shutil.rmtree(worktree)
