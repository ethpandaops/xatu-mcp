"""Abstract base class for sandbox backends."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExecutionResult:
    """Result of code execution in a sandbox."""

    stdout: str
    stderr: str
    exit_code: int
    execution_id: str = ""
    output_files: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0


class SandboxBackend(ABC):
    """Abstract base class for sandbox execution backends.

    Sandbox backends are responsible for executing Python code in an isolated
    environment. Different backends provide different levels of isolation:

    - DockerBackend: Uses standard Docker containers. Works everywhere including
      macOS and Windows. Provides process-level isolation but shares the kernel
      with the host.

    - GVisorBackend: Uses Docker with gVisor runtime (runsc). Provides user-space
      kernel isolation, significantly harder to escape. Linux only.

    - FirecrackerBackend: Uses Firecracker microVMs. Maximum isolation with
      dedicated VM per execution. Linux only. (Future implementation)
    """

    def __init__(
        self,
        image: str,
        timeout: int,
        memory_limit: str,
        cpu_limit: float,
        network: str,
        host_shared_path: str | None = None,
    ) -> None:
        """Initialize the sandbox backend.

        Args:
            image: Docker image to use for the sandbox.
            timeout: Maximum execution time in seconds.
            memory_limit: Memory limit (e.g., "2g", "512m").
            cpu_limit: CPU limit as a float (e.g., 1.0 = 1 CPU).
            network: Docker network to attach the container to.
            host_shared_path: Path on Docker host for shared files (for Docker-in-Docker).
        """
        self.image = image
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.network = network
        self.host_shared_path = host_shared_path

    @abstractmethod
    async def execute(
        self,
        code: str,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> ExecutionResult:
        """Execute Python code in the sandbox.

        Args:
            code: Python code to execute.
            env: Additional environment variables to set in the sandbox.
            timeout: Override the default timeout for this execution.

        Returns:
            ExecutionResult containing stdout, stderr, exit code, and output files.

        Raises:
            TimeoutError: If execution exceeds the timeout.
            RuntimeError: If there's an error starting or managing the sandbox.
        """
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up any resources held by the backend.

        This should be called when the server is shutting down to ensure
        all containers are properly terminated and resources are freed.
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this backend for logging/metrics."""
        pass
