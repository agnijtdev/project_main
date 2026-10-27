from abc import ABC, abstractmethod
from typing import Dict, Optional, Any
from devsecops_agent.schemas.exploit import ExecutionResult


class BaseSandbox(ABC):
    """Abstract base class for isolated sandbox execution environments."""

    def __init__(self, workspace_path: str, timeout: int = 45):
        self.workspace_path = workspace_path
        self.timeout = timeout
        self.is_running = False

    @abstractmethod
    def start(self) -> None:
        """Initialize and start the sandbox environment."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop and tear down the sandbox environment."""
        pass

    @abstractmethod
    def execute(self, command: str, timeout: Optional[int] = None) -> ExecutionResult:
        """Execute a shell command inside the sandbox."""
        pass

    @abstractmethod
    def write_file(self, relative_path: str, content: str) -> None:
        """Write content to a file inside the sandbox."""
        pass

    @abstractmethod
    def read_file(self, relative_path: str) -> str:
        """Read content from a file inside the sandbox."""
        pass

    @abstractmethod
    def apply_patch(self, modified_files: Dict[str, str]) -> None:
        """Apply a set of modified file contents to the sandbox."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset the sandbox back to the initial workspace state."""
        pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
