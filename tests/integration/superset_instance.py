import subprocess
import time
from pathlib import Path

import requests


class SupersetInstance:
    """Manage a Superset instance for integration tests."""

    def __init__(self, url: str, user: str, password: str):
        self.url = url
        self.password = password
        self.user = user

    def is_running(self) -> bool:
        """Check if the Superset stack is running and healthy."""
        try:
            resp = requests.get(f"{self.url}/health", timeout=5)
            return resp.status_code == 200
        except requests.exceptions.ConnectionError:
            return False


class SupersetDockerComposeInstance(SupersetInstance):
    """Managed superset docker stack"""

    def __init__(self, compose_file: Path, project_name="superset_test") -> None:
        self.compose_file = compose_file
        self.project_name = project_name
        super().__init__("http://localhost:8088", "admin", "admin")

    def _compose_base_cmd(self) -> list[str]:
        return [
            "docker",
            "compose",
            "-f",
            str(self.compose_file),
            "-p",
            self.project_name,
        ]

    def _is_compose_stack_running(self) -> bool:
        """
        Return True if any container in this compose project is currently running.
        """
        # Preferred (newer Docker Compose): `ps --status running -q`
        cmd = [*self._compose_base_cmd(), "ps", "--status", "running", "-q"]
        res = subprocess.run(cmd, capture_output=True, text=True)

        if res.returncode == 0:
            return bool(res.stdout.strip())

        # Fallback for older Docker Compose (no --status):
        # `ps -q` then inspect each container state.
        cmd = [*self._compose_base_cmd(), "ps", "-q"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return False

        container_ids = [c for c in res.stdout.splitlines() if c.strip()]
        if not container_ids:
            return False

        insp = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", *container_ids],
            capture_output=True,
            text=True,
        )
        if insp.returncode != 0:
            return False

        return any(line.strip() == "true" for line in insp.stdout.splitlines())

    def start(self, timeout: int = 120):
        """Start the docker-compose stack and wait for Superset to be ready."""
        if not self._is_compose_stack_running():
            print("Starting docker container...")
            cmd = [
                *self._compose_base_cmd(),
                "up",
                "-d",
            ]
            subprocess.run(cmd, check=True, capture_output=True)

        # Wait for Superset health check
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                resp = requests.get(f"{self.url}/health", timeout=1)
                if resp.status_code == 200:
                    return
            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
            ):
                pass
            time.sleep(1)

        raise TimeoutError(f"Superset not ready after {timeout} seconds")

    def stop(self):
        """Stop and remove the docker-compose stack."""
        cmd = [
            *self._compose_base_cmd(),
            "down",
            "-v",
            "--remove-orphans",
        ]
        subprocess.run(cmd, capture_output=True)

    @staticmethod
    def validate_docker_installed():
        # Check if docker-compose is available
        try:
            subprocess.run(
                ["docker", "compose", "--version"], capture_output=True, check=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise ValueError("docker-compose not available")

        # Check if Docker is running
        try:
            subprocess.run(["docker", "info"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise ValueError("Docker not available")
