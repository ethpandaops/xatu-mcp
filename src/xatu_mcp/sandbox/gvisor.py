"""gVisor sandbox backend for secure code execution."""

import asyncio
import tempfile
import threading
import uuid
from pathlib import Path

import docker
import structlog

from xatu_mcp.sandbox.base import ExecutionResult, SandboxBackend

logger = structlog.get_logger()

# Execution ID prefix length for unique container identification
EXECUTION_ID_LENGTH = 8


class GVisorBackend(SandboxBackend):
    """gVisor-based sandbox backend.

    Uses Docker with the gVisor runtime (runsc) for enhanced isolation.
    gVisor provides a user-space kernel that intercepts system calls,
    providing significantly stronger isolation than standard containers.

    This is the recommended backend for production deployments on Linux.
    Note: gVisor only works on Linux hosts.
    """

    RUNTIME = "runsc"

    def __init__(
        self,
        image: str,
        timeout: int,
        memory_limit: str,
        cpu_limit: float,
        network: str,
        host_shared_path: str | None = None,
    ) -> None:
        super().__init__(image, timeout, memory_limit, cpu_limit, network, host_shared_path)
        self._client: docker.DockerClient | None = None
        self._active_containers: dict[str, docker.models.containers.Container] = {}
        self._lock = threading.Lock()  # Thread-safe access to _active_containers
        self._runtime_checked = False

    @property
    def client(self) -> docker.DockerClient:
        """Get or create Docker client."""
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    @property
    def name(self) -> str:
        return "gvisor"

    def _track_container(self, execution_id: str, container: docker.models.containers.Container) -> None:
        """Thread-safe container tracking."""
        with self._lock:
            self._active_containers[execution_id] = container

    def _untrack_container(self, execution_id: str) -> docker.models.containers.Container | None:
        """Thread-safe container untracking. Returns the container if it was tracked."""
        with self._lock:
            return self._active_containers.pop(execution_id, None)

    def _force_kill_container(self, execution_id: str) -> None:
        """Force kill a container by execution_id (used on timeout)."""
        container = self._untrack_container(execution_id)
        if container:
            try:
                logger.warning("Force killing timed out gVisor container", execution_id=execution_id)
                container.kill()
                container.remove(force=True)
            except docker.errors.NotFound:
                pass  # Already removed
            except Exception as e:
                logger.error("Failed to force kill container", execution_id=execution_id, error=str(e))

    def _check_runtime(self) -> None:
        """Check if gVisor runtime is available."""
        if self._runtime_checked:
            return

        try:
            info = self.client.info()
            runtimes = info.get("Runtimes", {})
            if self.RUNTIME not in runtimes:
                available = list(runtimes.keys())
                raise RuntimeError(
                    f"gVisor runtime '{self.RUNTIME}' not found. "
                    f"Available runtimes: {available}. "
                    "Install gVisor: https://gvisor.dev/docs/user_guide/install/"
                )
            self._runtime_checked = True
            logger.info("gVisor runtime verified", runtime=self.RUNTIME)
        except docker.errors.APIError as e:
            raise RuntimeError(f"Failed to check Docker runtimes: {e}")

    async def execute(
        self,
        code: str,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> ExecutionResult:
        """Execute Python code in a gVisor-isolated container.

        Args:
            code: Python code to execute.
            env: Additional environment variables.
            timeout: Override default timeout.

        Returns:
            ExecutionResult with stdout, stderr, exit code, and output files.
        """
        # Check runtime availability on first execution
        self._check_runtime()

        execution_timeout = timeout or self.timeout
        execution_id = str(uuid.uuid4())[:EXECUTION_ID_LENGTH]

        # Create temp directories for shared files and output
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            shared_dir = tmpdir_path / "shared"
            output_dir = tmpdir_path / "output"
            # Set permissions so 'nobody' user can access these directories
            # shared_dir: 0755 (readable by nobody)
            # output_dir: 0777 (writable by nobody)
            shared_dir.mkdir(mode=0o755)
            output_dir.mkdir(mode=0o777)

            # Write the code to a file
            script_path = shared_dir / "script.py"
            script_path.write_text(code)

            # Build environment variables
            container_env = env.copy() if env else {}

            # Set HOME and cache directories to /tmp for 'nobody' user
            # This allows libraries like matplotlib to write their config/cache
            container_env.setdefault("HOME", "/tmp")
            container_env.setdefault("MPLCONFIGDIR", "/tmp")
            container_env.setdefault("XDG_CACHE_HOME", "/tmp")

            # Build volume mounts
            volumes = {
                str(shared_dir): {"bind": "/shared", "mode": "ro"},
                str(output_dir): {"bind": "/output", "mode": "rw"},
            }

            logger.debug(
                "Starting gVisor container",
                execution_id=execution_id,
                image=self.image,
                timeout=execution_timeout,
                runtime=self.RUNTIME,
            )

            try:
                # Run container in a thread pool to not block the event loop
                result = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: self._run_container(
                            execution_id,
                            volumes,
                            container_env,
                            execution_timeout,
                        ),
                    ),
                    timeout=execution_timeout + 5,
                )
            except asyncio.TimeoutError:
                # Force kill the container that's still running
                self._force_kill_container(execution_id)
                logger.warning(
                    "gVisor container execution timed out",
                    execution_id=execution_id,
                )
                raise TimeoutError(f"Execution timed out after {execution_timeout}s")

            # Collect output files (note: S3 uploads are done by user code via xatu.storage)
            output_files = []
            for f in output_dir.iterdir():
                if f.is_file() and not f.name.startswith("."):
                    output_files.append(f.name)

            # Read metrics if present
            metrics = {}
            metrics_file = output_dir / ".metrics.json"
            if metrics_file.exists():
                import json

                try:
                    metrics = json.loads(metrics_file.read_text())
                except json.JSONDecodeError:
                    logger.warning("Failed to parse metrics file", execution_id=execution_id)

            return ExecutionResult(
                stdout=result["stdout"],
                stderr=result["stderr"],
                exit_code=result["exit_code"],
                execution_id=execution_id,
                output_files=output_files,
                metrics=metrics,
                duration_seconds=result["duration"],
            )

    def _run_container(
        self,
        execution_id: str,
        volumes: dict,
        env: dict[str, str],
        timeout: int,
    ) -> dict:
        """Run the container synchronously with gVisor runtime.

        gVisor provides additional isolation at the kernel level, but we still
        apply container-level security hardening for defense in depth.
        """
        import time

        start_time = time.time()
        container = None

        try:
            container = self.client.containers.run(
                self.image,
                command=["python", "/shared/script.py"],
                volumes=volumes,
                environment=env,
                network=self.network,
                mem_limit=self.memory_limit,
                cpu_period=100000,
                cpu_quota=int(100000 * self.cpu_limit),
                runtime=self.RUNTIME,  # Use gVisor runtime
                remove=False,
                detach=True,
                stderr=True,
                stdout=True,
                # Security hardening options (defense in depth with gVisor)
                user="nobody",  # Run as non-root user
                read_only=True,  # Read-only root filesystem
                security_opt=["no-new-privileges:true"],  # Prevent privilege escalation
                cap_drop=["ALL"],  # Drop all Linux capabilities
                tmpfs={"/tmp": "size=100M,mode=1777"},  # Writable /tmp in memory
                pids_limit=100,  # Limit number of processes
            )

            # Track container for potential timeout cleanup
            self._track_container(execution_id, container)

            # Wait for container to finish
            result = container.wait(timeout=timeout)
            exit_code = result.get("StatusCode", 1)

            # Get logs
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

            duration = time.time() - start_time

            logger.debug(
                "gVisor container finished",
                execution_id=execution_id,
                exit_code=exit_code,
                duration=duration,
            )

            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "duration": duration,
            }

        except docker.errors.ContainerError as e:
            duration = time.time() - start_time
            return {
                "stdout": "",
                "stderr": str(e),
                "exit_code": e.exit_status,
                "duration": duration,
            }

        except Exception as e:
            duration = time.time() - start_time
            logger.error("gVisor container error", execution_id=execution_id, error=str(e))
            return {
                "stdout": "",
                "stderr": f"Container error: {e}",
                "exit_code": 1,
                "duration": duration,
            }

        finally:
            # Untrack and remove container
            self._untrack_container(execution_id)
            if container:
                try:
                    container.remove(force=True)
                except docker.errors.NotFound:
                    pass  # Already removed (e.g., by force kill on timeout)
                except Exception as e:
                    logger.warning(
                        "Failed to remove container",
                        execution_id=execution_id,
                        error=str(e),
                    )

    async def cleanup(self) -> None:
        """Clean up any active containers."""
        with self._lock:
            containers_to_cleanup = list(self._active_containers.items())
            self._active_containers.clear()

        for execution_id, container in containers_to_cleanup:
            try:
                container.kill()
                container.remove(force=True)
                logger.debug("Cleaned up gVisor container", execution_id=execution_id)
            except docker.errors.NotFound:
                pass  # Already removed
            except Exception as e:
                logger.warning(
                    "Failed to cleanup container",
                    execution_id=execution_id,
                    error=str(e),
                )

        if self._client:
            self._client.close()
            self._client = None
