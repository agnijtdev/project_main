import logging
from devsecops_agent.sandbox.base import BaseSandbox
from devsecops_agent.sandbox.local_sandbox import LocalIsolatedSandbox
from devsecops_agent.sandbox.docker_sandbox import DockerSandbox, DOCKER_AVAILABLE

logger = logging.getLogger(__name__)


def create_sandbox(workspace_path: str, driver: str = "auto", timeout: int = 45) -> BaseSandbox:
    """
    Factory function to instantiate the appropriate sandbox.
    If 'docker' is requested or 'auto' and Docker is running, uses DockerSandbox.
    Otherwise gracefully falls back to LocalIsolatedSandbox.
    """
    if driver == "docker":
        if DockerSandbox.is_docker_daemon_ready():
            logger.info("Instantiating Docker container sandbox.")
            return DockerSandbox(workspace_path=workspace_path, timeout=timeout)
        else:
            raise RuntimeError("Docker sandbox was explicitly requested but Docker daemon is unreachable.")

    if driver == "auto":
        if DockerSandbox.is_docker_daemon_ready():
            logger.info("Docker daemon detected. Using Docker container sandbox.")
            return DockerSandbox(workspace_path=workspace_path, timeout=timeout)
        else:
            logger.info("Docker daemon not active or unreachable. Falling back to LocalIsolatedSandbox.")
            return LocalIsolatedSandbox(workspace_path=workspace_path, timeout=timeout)

    return LocalIsolatedSandbox(workspace_path=workspace_path, timeout=timeout)


__all__ = ["BaseSandbox", "LocalIsolatedSandbox", "DockerSandbox", "create_sandbox"]
