import logging
import os
import shutil
from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv

from superset_io.utils import get_version

from .api import SupersetApiClient, SupersetApiSession

# Load env vars also from .env
load_dotenv()

log = logging.getLogger("superset_io")
logging.basicConfig(level="INFO")

superset_api: SupersetApiClient | None = None

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main(
    base_url: Annotated[
        str,
        typer.Option(
            help="Base URL for Superset instance",
            envvar="SUPERSET_BASE_URL",
        ),
    ] = "http://localhost:8088",
    username: Annotated[
        str,
        typer.Option(
            help="Username for Superset user",
            envvar="SUPERSET_USER",
        ),
    ] = "admin",
    password: Annotated[
        str | None,
        typer.Option(
            help="Password for Superset user",
            envvar="SUPERSET_PASSWORD_FILE",
            hide_input=True,
        ),
    ] = None,
    access_token: Annotated[
        str | None,
        typer.Option(
            help="Access token as alternative to user and password",
            hide_input=True,
            envvar="SUPERSET_ACCESS_TOKEN",
        ),
    ] = None,
):
    r"""
    Superset-IO

    Automate import, export, and exploration of Superset assets
    via the Superset REST API.

    © coasti
    """

    authenticate(
        base_url,
        username,
        password,
        access_token,
    )


def authenticate(
    base_url: str,
    username: str | None = None,
    password: str | None = None,
    access_token: str | None = None,
):
    """
    Initialize the global superset_api by asking users to input their credentials.

    Runs before each api call.

    helpful:
    https://stackoverflow.com/questions/68646596/how-to-get-superset-token-for-use-rest-api
    """

    global superset_api

    if superset_api is not None:
        log.debug("Using existing authenticated session")
        return

    log.info(f"Connecting to Superset at: {base_url}")

    if access_token is None:
        if password_file := os.environ.get("SUPERSET_PASSWORD_FILE", ""):
            password = Path(password_file).read_text().rstrip()

        user: str = username or typer.prompt("Username", type=str)
        log.info(f"Connecting to Superset as: {user}")
        session = SupersetApiSession.from_credentials(
            base_url=base_url,
            username=user,
            password=password or typer.prompt("Password", type=str, hide_input=True),
        )
    else:
        log.debug("Authenticating using access token")
        session = SupersetApiSession.from_token(
            base_url=base_url,
            bearer_token=access_token,
        )

    superset_api = SupersetApiClient(session)


@app.command()
def version():
    """Shows version and exit."""
    log.info(f"Coasti version {get_version()}")

    from importlib import metadata

    try:
        return metadata.version("coasti")
    except metadata.PackageNotFoundError:
        return "[not found] Use `uv sync` when developing!"


@app.command()
def test():
    """Test the connection to configured superset instance."""

    assert superset_api is not None
    superset_api.test_connection()


@app.command()
def download(
    dst_path: Annotated[
        Path,
        typer.Argument(
            file_okay=True,
            dir_okay=True,
            help="Destination zip or directory.",
        ),
    ],
):
    """Download all assets from server to zip or yaml directory."""

    if dst_path.is_dir() and any(dst_path.iterdir()):
        if typer.prompt(
            f"Destination directory '{dst_path}' is not empty. Delete and re-use?",
            type=bool,
            default=False,
        ):
            shutil.rmtree(dst_path)
        else:
            log.info("Exiting")
            raise typer.Exit(code=1)

    assert superset_api is not None
    superset_api.assets.download(dst_path)


@app.command()
def upload(
    src_path: Annotated[
        Path,
        typer.Argument(
            file_okay=True,
            dir_okay=True,
            exists=True,
            help="Source zip or directory.",
        ),
    ],
):
    """Upload all assets from zip or yaml directory to server."""

    assert superset_api is not None
    superset_api.assets.upload(src_path)
