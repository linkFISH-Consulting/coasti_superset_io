"""
Pytest configuration and shared fixtures for superset-io tests.
"""

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from superset_io.api import SupersetApiClient

from .superset_instance import (
    SupersetDockerComposeInstance,
    SupersetInstance,
)

log = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def superset_url(request) -> str:
    """Return the Superset base URL for integration tests."""
    return request.config.getoption("--superset-url")


@pytest.fixture(scope="session")
def superset_credentials(request):
    """Return Superset credentials as a tuple (username, password)."""
    username = request.config.getoption("--superset-username")
    password = request.config.getoption("--superset-password")
    return username, password


@pytest.fixture(scope="session")
def superset_instance(
    request, superset_url, superset_credentials
) -> Iterator[SupersetInstance | None]:
    """
    Start a Superset docker-compose stack if --start-docker flag is provided.

    Yields a SupersetDockerCompose instance. The stack is automatically
    stopped after the test session.
    """
    instance: SupersetInstance
    if not request.config.getoption("--start-docker"):
        log.debug("Not starting docker; assuming Superset is already available.")
        instance = SupersetInstance(
            url=superset_url,
            user=superset_credentials[0],
            password=superset_credentials[1],
        )
    else:
        compose_file = Path(__file__).parent / "docker-compose.yml"
        if not compose_file.exists():
            raise ValueError("Compose file not found!")
        instance = SupersetDockerComposeInstance(compose_file=compose_file)
        instance.validate_docker_installed()
        instance.start()

    # Check connection
    if not instance.is_running():
        raise ValueError("Could not establish connection to test superset instance")

    try:
        yield instance
    finally:
        if isinstance(instance, SupersetDockerComposeInstance):
            if not instance.was_running:
                instance.stop()


@pytest.fixture
def superset_client(superset_instance: SupersetInstance) -> SupersetApiClient:
    from superset_io.api import SupersetApiClient
    from superset_io.session import SupersetApiSession

    session = SupersetApiSession.from_credentials(
        superset_instance.url, superset_instance.user, superset_instance.password
    )

    return SupersetApiClient(session)
