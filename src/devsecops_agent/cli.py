import io
import re
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table

from devsecops_agent.config import settings
from devsecops_agent.context.extractor import ContextExtractor
from devsecops_agent.orchestrator.pipeline import OrchestrationPipeline
from devsecops_agent.schemas.pipeline import PipelineStage

app = typer.Typer(
    help="Autonomous Multi-Agent Framework for Containerized Vulnerability Exploitation and Remediation"
)
console = Console()


@app.command()
def scan(
    repo: str = typer.Option(".", help="Path to local repository or remote GitHub git URL"),
    base_branch: Optional[str] = typer.Option(None, help="Base Git branch (e.g. main)"),
    head_branch: Optional[str] = typer.Option(None, help="Head/PR Git branch (e.g. feature/pr)"),
    diff_file: Optional[str] = typer.Option(None, help="Optional path to static diff file (fallback)"),
    test_cmd: str = typer.Option("pytest", help="Regression test command to execute in sandbox"),
    driver: str = typer.Option("docker", help="Sandbox driver: docker, auto, or local"),
    provider: Optional[str] = typer.Option(None, help="LLM Provider: gemini, openai, ollama, or mock"),
    api_key: Optional[str] = typer.Option(None, help="API Key for hosted LLM provider"),
    create_branch: bool = typer.Option(
        True,
        "--create-branch/--no-create-branch",
        help="Create a separate committed remediation branch after verification.",
    ),
    output_report: Optional[str] = typer.Option("reports/remediation_report.md", help="Path to write output markdown report")
):
    """
    Analyzes code changes in a Pull Request, confirms vulnerabilities via dynamic exploitation,
    and synthesizes verified non-regressive patches.
    """
    console.print(
        "[bold cyan]Autonomous Multi-Agent DevSecOps Framework[/bold cyan] [green](CET Group 14)[/green]"
    )

    # 1. Handle remote Git repository URL (e.g. https://github.com/...)
    temp_clone_dir = None
    if repo.startswith("http://") or repo.startswith("https://") or repo.startswith("git@"):
        temp_clone_dir = tempfile.mkdtemp(prefix="devsecops_repo_")
        console.print(f"• Cloning remote repository [italic]{repo}[/italic] into sandbox workspace...")
        subprocess.run(["git", "clone", repo, temp_clone_dir], check=True)
        repo_path = Path(temp_clone_dir).resolve()
    else:
        repo_path = Path(repo).resolve()
        if not repo_path.exists():
            console.print(f"[bold red]Error:[/bold red] Repository path '{repo}' not found.")
            raise typer.Exit(code=1)

    # Configure LLM provider override if specified
    if provider:
        settings.LLM_PROVIDER = provider
    if api_key:
        if settings.LLM_PROVIDER == "gemini":
            settings.GEMINI_API_KEY = api_key
        else:
            settings.OPENAI_API_KEY = api_key
            settings.HOSTED_LLM_API_KEY = api_key

    console.print(f"• Active LLM Provider: [bold yellow]{settings.LLM_PROVIDER.upper()}[/bold yellow]")
    console.print(f"• Sandbox Driver: [bold blue]{driver.upper()}[/bold blue]")

    extractor = ContextExtractor(str(repo_path))

    # Extract Git PR diff directly from repository
    if diff_file:
        df = Path(diff_file)
        if df.exists():
            diff_text = df.read_text(encoding="utf-8")
            console.print(f"• Loaded diff from file: [italic]{diff_file}[/italic]")
        else:
            console.print(f"[bold red]Error:[/bold red] Diff file '{diff_file}' not found.")
            raise typer.Exit(code=1)
    else:
        diff_text = extractor.get_git_diff(base_branch, head_branch)
        if base_branch and head_branch:
            console.print(f"• Extracted Git PR diff: [italic]{base_branch}...{head_branch}[/italic]")
        elif base_branch:
            console.print(f"• Extracted Git diff against: [italic]{base_branch}[/italic]")
        else:
            console.print("• Extracted Git diff from repository HEAD")

    if not diff_text.strip():
        console.print("[yellow]No code changes detected in the specified Git range.[/yellow]")
        return

    # Read and execute the PR head tree even when main is checked out.
    analysis_path = repo_path
    snapshot = None
    if head_branch:
        current_branch = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=str(repo_path), capture_output=True, text=True, check=False,
        ).stdout.strip()
        if current_branch != head_branch:
            archive = subprocess.run(
                ["git", "archive", "--format=tar", head_branch],
                cwd=str(repo_path), capture_output=True, check=False,
            )
            if archive.returncode:
                console.print(
                    f"[bold red]Could not read head branch '{head_branch}':[/bold red] "
                    f"{archive.stderr.decode(errors='replace')}"
                )
                raise typer.Exit(code=1)
            snapshot = tempfile.TemporaryDirectory(prefix="devsecops-head-")
            with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as bundle:
                bundle.extractall(snapshot.name)
            analysis_path = Path(snapshot.name)
            console.print(f"• Analysis source: PR head branch [italic]{head_branch}[/italic]")

    extractor = ContextExtractor(str(analysis_path))
    candidates = extractor.extract_candidates_from_diff(diff_text)
    if not candidates:
        if snapshot:
            snapshot.cleanup()
        console.print("[yellow]No Python changes or vulnerability candidates detected in diff.[/yellow]")
        return

    console.print(f"Extracted [bold]{len(candidates)}[/bold] candidate(s) for verification.")

    orchestrator = OrchestrationPipeline(
        repo_path=str(analysis_path),
        sandbox_driver=driver,
        test_command=test_cmd
    )

    pr_ref = f"{base_branch or 'main'}...{head_branch or 'HEAD'}"
    report = orchestrator.run(candidates, pr_ref=pr_ref)
    if snapshot:
        snapshot.cleanup()

    # Print summary table
    table = Table(title="Autonomous Remediation Summary")
    table.add_column("Candidate ID", style="cyan")
    table.add_column("OWASP Category", style="magenta")
    table.add_column("Exploit Confirmed", style="yellow")
    table.add_column("Remediation Status", style="green")

    for rec in report.records:
        confirmed = "YES" if (rec.exploit_report and rec.exploit_report.confirmed) else "NO"
        status_color = "green" if rec.status == PipelineStage.REMEDIATION_SUCCESS else "red"
        table.add_row(
            rec.candidate.id,
            rec.candidate.owasp_category.value,
            confirmed,
            f"[{status_color}]{rec.status.value}[/{status_color}]"
        )

    console.print(table)

    remediation_branch = None
    remediation_worktree = None
    if create_branch and report.successfully_remediated > 0:
        source_ref = head_branch or _current_branch(repo_path)
        try:
            remediation_branch, remediation_worktree = _create_remediation_branch(
                repo_path, source_ref, report.records
            )
        except (OSError, RuntimeError, ValueError) as exc:
            console.print(f"[bold red]Could not create remediation branch:[/bold red] {exc}")
        if remediation_branch:
            report.summary_markdown += (
                f"\n\n## Verified Remediation Branch\n"
                f"- **Branch:** `{remediation_branch}`\n"
                f"- **Checkout:** `{remediation_worktree}`\n"
                f"- **Based on:** `{source_ref}`\n"
            )

    if remediation_branch:
        console.print(f"[bold green]Created remediation branch:[/bold green] {remediation_branch}")
        console.print(f"[bold green]Branch checkout:[/bold green] {remediation_worktree}")
    elif create_branch and report.successfully_remediated == 0:
        console.print("[yellow]No remediation branch created: no candidate completed verified remediation.[/yellow]")

    if output_report:
        out_p = Path(output_report)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(report.summary_markdown, encoding="utf-8")
        console.print(f"[bold green]Report written to:[/bold green] {output_report}")


def _current_branch(repo_path: Path) -> str:
    result = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=str(repo_path), capture_output=True, text=True, check=False,
    )
    branch = result.stdout.strip()
    if result.returncode or not branch:
        raise RuntimeError("could not determine the current source branch")
    return branch


def _create_remediation_branch(repo_path, source_ref, records):
    """Apply verified patches in a new checkout without switching source branches."""
    verified_files = {}
    for record in records:
        if record.status != PipelineStage.REMEDIATION_SUCCESS or not record.final_verified_patch:
            continue
        for relative_path, content in record.final_verified_patch.modified_files.items():
            normalized = Path(relative_path.replace("\\", "/"))
            if normalized.is_absolute() or ".." in normalized.parts or ".git" in normalized.parts:
                raise ValueError(f"patch contains an unsafe path: {relative_path}")
            key = normalized.as_posix()
            if key in verified_files and verified_files[key] != content:
                raise ValueError(f"verified patches conflict on '{key}'; no branch was created")
            verified_files[key] = content

    if not verified_files:
        return None, None

    slug = re.sub(r"[^a-z0-9-]+", "-", source_ref.lower()).strip("-")[:48] or "head"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base_name = f"vulnerability/remediation-{slug}-{stamp}"
    worktree_root = repo_path.parent / f"{repo_path.name}-remediation-{slug}-{stamp}"
    branch_name = base_name
    suffix = 1
    while True:
        exists = subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", f"refs/heads/{branch_name}"],
            cwd=str(repo_path), check=False,
        ).returncode == 0
        candidate_path = worktree_root if suffix == 1 else worktree_root.with_name(f"{worktree_root.name}-{suffix}")
        if not exists and not candidate_path.exists():
            worktree_path = candidate_path
            break
        suffix += 1
        branch_name = f"{base_name}-{suffix}"

    add_result = subprocess.run(
        ["git", "worktree", "add", "-b", branch_name, str(worktree_path), source_ref],
        cwd=str(repo_path), capture_output=True, text=True, check=False,
    )
    if add_result.returncode:
        raise RuntimeError(add_result.stderr.strip() or "git worktree add failed")

    try:
        for relative_path, content in verified_files.items():
            target = (worktree_path / relative_path).resolve()
            try:
                target.relative_to(worktree_path.resolve())
            except ValueError as exc:
                raise ValueError(f"patch path escapes remediation checkout: {relative_path}") from exc
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        add_files = subprocess.run(
            ["git", "add", "--", *verified_files.keys()],
            cwd=str(worktree_path), capture_output=True, text=True, check=False,
        )
        if add_files.returncode:
            raise RuntimeError(add_files.stderr.strip() or "could not stage verified files")

        commit_args = ["git"]
        identity_name = subprocess.run(
            ["git", "config", "user.name"], cwd=str(worktree_path), capture_output=True, text=True, check=False
        ).stdout.strip()
        identity_email = subprocess.run(
            ["git", "config", "user.email"], cwd=str(worktree_path), capture_output=True, text=True, check=False
        ).stdout.strip()
        if not identity_name:
            commit_args.extend(["-c", "user.name=DevSecOps Remediation Agent"])
        if not identity_email:
            commit_args.extend(["-c", "user.email=devsecops-agent@localhost"])
        commit_args.extend(["commit", "-m", f"Apply verified remediation for {source_ref}"])
        commit = subprocess.run(
            commit_args, cwd=str(worktree_path), capture_output=True, text=True, check=False
        )
        if commit.returncode:
            raise RuntimeError(commit.stderr.strip() or "could not commit verified remediation")
    except Exception:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree_path)],
            cwd=str(repo_path), capture_output=True, text=True, check=False,
        )
        subprocess.run(
            ["git", "branch", "-D", branch_name],
            cwd=str(repo_path), capture_output=True, text=True, check=False,
        )
        raise

    return branch_name, worktree_path


@app.command()
def version():
    """Display system version and configuration."""
    from devsecops_agent import __version__
    console.print(f"[bold cyan]DevSecOps Multi-Agent Version:[/bold cyan] {__version__}")


if __name__ == "__main__":
    app()
