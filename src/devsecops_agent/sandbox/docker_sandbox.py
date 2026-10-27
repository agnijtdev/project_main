import io
import os
import shlex
import tarfile
import time
from pathlib import Path
from typing import Dict, Optional
from devsecops_agent.sandbox.base import BaseSandbox
from devsecops_agent.schemas.exploit import ExecutionResult

try:
    import docker
    from docker.errors import DockerException
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False


class DockerSandbox(BaseSandbox):
    """
    Containerized isolated sandbox using Docker.
    Mounts or copies workspace into an ephemeral Docker container.
    """

    DEFAULT_IMAGE = "devsecops-sandbox:latest"

    def __init__(self, workspace_path: str, timeout: int = 45, image: Optional[str] = None):
        super().__init__(workspace_path, timeout)
        self.image = image or self.DEFAULT_IMAGE
        self.client = None
        self.container = None
        self._original_snapshots: Dict[str, str] = {}

    @classmethod
    def is_docker_daemon_ready(cls) -> bool:
        if not DOCKER_AVAILABLE:
            return False
        try:
            client = docker.from_env()
            client.ping()
            return True
        except Exception:
            return False

    def start(self) -> None:
        if not DOCKER_AVAILABLE:
            raise RuntimeError("docker Python package is not installed.")
        try:
            self.client = docker.from_env()
            self.client.ping()
        except Exception as e:
            raise RuntimeError(f"Cannot connect to Docker daemon: {e}")

        # Start ephemeral detached container
        container_name = f"devsecops_sandbox_{int(time.time())}"
        self.container = self.client.containers.run(
            image=self.image,
            name=container_name,
            command="tail -f /dev/null",
            working_dir="/workspace",
            detach=True,
            remove=True
        )

        # Copy workspace files into /workspace in container
        self._copy_local_to_container(Path(self.workspace_path), "/workspace")
        self.is_running = True

    def stop(self) -> None:
        if self.container:
            try:
                self.container.stop(timeout=2)
            except Exception:
                pass
            self.container = None
        self.is_running = False

    def _copy_local_to_container(self, local_src: Path, container_dest: str) -> None:
        if not local_src.exists() or not self.container:
            return

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            for item in local_src.rglob("*"):
                if any(ignored in item.parts for ignored in [".git", "__pycache__", ".pytest_cache", ".sandbox_scratch"]) or item.name == ".env":
                    continue
                rel_path = item.relative_to(local_src)
                tar.add(item, arcname=str(rel_path))
        tar_stream.seek(0)
        self.container.put_archive(path=container_dest, data=tar_stream.read())

    def write_file(self, relative_path: str, content: str) -> None:
        if not self.container:
            raise RuntimeError("Container is not active.")

        tar_stream = io.BytesIO()
        data = content.encode("utf-8")
        tar_info = tarfile.TarInfo(name=relative_path)
        tar_info.size = len(data)
        tar_info.mtime = int(time.time())

        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            tar.addfile(tar_info, io.BytesIO(data))
        tar_stream.seek(0)

        dest_dir = os.path.dirname(f"/workspace/{relative_path}")
        self.container.exec_run(f"mkdir -p {dest_dir}")
        self.container.put_archive(path=dest_dir, data=tar_stream.read())

    def read_file(self, relative_path: str) -> str:
        if not self.container:
            raise RuntimeError("Container is not active.")
        exec_res = self.container.exec_run(f"cat /workspace/{relative_path}")
        if exec_res.exit_code != 0:
            raise FileNotFoundError(f"Failed to read {relative_path} from container.")
        return exec_res.output.decode("utf-8")

    def apply_patch(self, modified_files: Dict[str, str]) -> None:
        for rel_path, content in modified_files.items():
            if rel_path not in self._original_snapshots:
                try:
                    self._original_snapshots[rel_path] = self.read_file(rel_path)
                except Exception:
                    pass
            self.write_file(rel_path, content)

    def reset(self) -> None:
        for rel_path, orig in self._original_snapshots.items():
            self.write_file(rel_path, orig)
        self._original_snapshots.clear()

    def execute(self, command: str, timeout: Optional[int] = None) -> ExecutionResult:
        if not self.container:
            raise RuntimeError("Container is not active.")

        cmd_timeout = timeout or self.timeout
        start_time = time.time()
        timed_out = False

        try:
            bounded_command = f"timeout --signal=TERM --kill-after=2 {int(cmd_timeout)}s /bin/sh -c {shlex.quote(command)}"
            exec_res = self.container.exec_run(
                cmd=["/bin/sh", "-c", bounded_command],
                workdir="/workspace",
                environment={"PYTHONPATH": "/workspace"},
                demux=True,
            )
            out, err = exec_res.output
            stdout = (out or b"").decode("utf-8", errors="replace")
            stderr = (err or b"").decode("utf-8", errors="replace")
            exit_code = exec_res.exit_code
            timed_out = exit_code == 124
        except Exception as e:
            stdout = ""
            stderr = f"Container execution error: {str(e)}"
            exit_code = -1

        duration = time.time() - start_time
        return ExecutionResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=round(duration, 3),
            timed_out=timed_out
        )
