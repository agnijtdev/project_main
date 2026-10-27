import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Dict, Optional
from devsecops_agent.sandbox.base import BaseSandbox
from devsecops_agent.schemas.exploit import ExecutionResult


class LocalIsolatedSandbox(BaseSandbox):
    """
    Subprocess-isolated sandbox environment.
    Copies workspace to a dedicated isolated scratch directory to safely execute code.
    """

    def __init__(self, workspace_path: str, timeout: int = 45):
        super().__init__(workspace_path, timeout)
        self.scratch_id = str(uuid.uuid4())[:8]
        self.sandbox_root: Optional[Path] = None
        self._original_snapshots: Dict[str, str] = {}

    def start(self) -> None:
        source_dir = Path(self.workspace_path).resolve()
        self.sandbox_root = Path(tempfile.mkdtemp(prefix=f"devsecops-sandbox-{self.scratch_id}-"))

        # Copy entire source workspace into isolated sandbox
        if source_dir.exists():
            shutil.copytree(
                source_dir,
                self.sandbox_root,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(".git", ".sandbox_scratch", "__pycache__", ".pytest_cache", ".env")
            )
        else:
            self.sandbox_root.mkdir(parents=True, exist_ok=True)

        self.is_running = True

    def stop(self) -> None:
        if self.sandbox_root and self.sandbox_root.exists():
            try:
                shutil.rmtree(self.sandbox_root, ignore_errors=True)
            except Exception:
                pass
        self.is_running = False

    def write_file(self, relative_path: str, content: str) -> None:
        if not self.sandbox_root:
            raise RuntimeError("Sandbox is not running.")
        target_path = self.sandbox_root / relative_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(content, encoding="utf-8")

    def read_file(self, relative_path: str) -> str:
        if not self.sandbox_root:
            raise RuntimeError("Sandbox is not running.")
        target_path = self.sandbox_root / relative_path
        if not target_path.exists():
            raise FileNotFoundError(f"File {relative_path} does not exist in sandbox.")
        return target_path.read_text(encoding="utf-8")

    def apply_patch(self, modified_files: Dict[str, str]) -> None:
        if not self.sandbox_root:
            raise RuntimeError("Sandbox is not running.")
        for rel_path, content in modified_files.items():
            # Snapshot original file if not recorded yet
            if rel_path not in self._original_snapshots:
                file_path = self.sandbox_root / rel_path
                if file_path.exists():
                    self._original_snapshots[rel_path] = file_path.read_text(encoding="utf-8")
            self.write_file(rel_path, content)

    def reset(self) -> None:
        if not self.sandbox_root:
            raise RuntimeError("Sandbox is not running.")
        for rel_path, original_content in self._original_snapshots.items():
            self.write_file(rel_path, original_content)
        self._original_snapshots.clear()

    def execute(self, command: str, timeout: Optional[int] = None) -> ExecutionResult:
        if not self.sandbox_root:
            raise RuntimeError("Sandbox is not running.")

        cmd_timeout = timeout or self.timeout
        start_time = time.time()
        timed_out = False

        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.sandbox_root)
        env["SANDBOX_ACTIVE"] = "1"

        try:
            process = subprocess.run(
                command,
                cwd=str(self.sandbox_root),
                shell=True,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=cmd_timeout,
                env=env
            )
            stdout = process.stdout
            stderr = process.stderr
            exit_code = process.returncode
        except subprocess.TimeoutExpired as te:
            timed_out = True
            stdout = te.stdout or ""
            stderr = (te.stderr or "") + f"\n[Execution Timed Out after {cmd_timeout} seconds]"
            exit_code = 124
        except Exception as e:
            stdout = ""
            stderr = f"Subprocess execution error: {str(e)}"
            exit_code = -1

        duration = time.time() - start_time
        return ExecutionResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout or "",
            stderr=stderr or "",
            duration_seconds=round(duration, 3),
            timed_out=timed_out
        )
