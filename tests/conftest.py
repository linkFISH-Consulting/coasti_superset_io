import os

import pytest

# ---------------------------------- Config ---------------------------------- #


def pytest_addoption(parser):
    """Add command-line options for pytest."""
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="Run integration tests (requires Superset instance)",
    )
    parser.addoption(
        "--superset-url",
        action="store",
        default=os.environ.get("SUPERSET_TEST_URL", "http://localhost:8088"),
        help="Superset base URL for integration tests",
    )
    parser.addoption(
        "--superset-username",
        action="store",
        default=os.environ.get("SUPERSET_TEST_USERNAME", "admin"),
        help="Superset username for integration tests",
    )
    parser.addoption(
        "--superset-password",
        action="store",
        default=os.environ.get("SUPERSET_TEST_PASSWORD", "admin"),
        help="Superset password for integration tests",
    )
    parser.addoption(
        "--start-docker",
        action="store",
        default=True,
        help="Starts & stops the superset docker container on test runs.",
    )


def pytest_configure(config):
    """Configure pytest based on options."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test (requires Superset)"
    )


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless --integration flag is provided.

    Mark a test by adding `@pytest.mark.integration` to it.
    """
    if not config.getoption("--integration"):
        skip_integration = pytest.mark.skip(
            reason="Integration tests require --integration flag"
        )
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)


# ---------------------------------------------------------------------------- #
