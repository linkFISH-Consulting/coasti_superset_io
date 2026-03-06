import logging
import os
import shutil
from pathlib import Path
from typing import Annotated

import requests
import typer
from dotenv import load_dotenv

from superset_io.api import SupersetApiClient, SupersetApiSession
from superset_io.utils import get_version

from .utils import Context, catch_exception

# Load env vars also from .env
load_dotenv()

log = logging.getLogger("superset_io")
logging.basicConfig(level="INFO")
app = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
# app.add_typer(explore_app)


@app.callback()
def main(
    ctx: Context,
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
    if not ctx.obj:
        authenticate(
            base_url,
            username,
            password,
            access_token,
        )


@catch_exception(
    exception=requests.ConnectionError,
    exit_code=1,
)
def authenticate(
    base_url: str,
    username: str | None = None,
    password: str | None = None,
    access_token: str | None = None,
) -> SupersetApiClient:
    """
    Initialize the global superset_api by asking users to input their credentials.

    Runs before each api call.

    helpful:
    https://stackoverflow.com/questions/68646596/how-to-get-superset-token-for-use-rest-api
    """

    log.info(f"Connecting to Superset at: {base_url}")

    if access_token is None:
        if password_file := os.environ.get("SUPERSET_PASSWORD_FILE", ""):
            password = Path(password_file).read_text().rstrip()

        user: str = username or typer.prompt("Username", type=str)
        log.info(f"Connecting to Superset as: {user}")
        session = SupersetApiSession.from_credentials(
            base_url=base_url,
            username=user,
            password=password
            or typer.prompt("Password", type=str, hide_input=True, default="admin"),
        )
    else:
        log.debug("Authenticating using access token")
        session = SupersetApiSession.from_token(
            base_url=base_url,
            bearer_token=access_token,
        )

    return SupersetApiClient(session)


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
@catch_exception(
    exception=requests.ConnectionError,
    exit_code=1,
)
def test(
    ctx: Context,
):
    """Test the connection to configured superset instance."""
    ctx.obj.test_connection()


@app.command()
def download(
    ctx: Context,
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

    ctx.obj.assets.download(dst_path)


@app.command()
def upload(
    ctx: Context,
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

    ctx.obj.assets.upload(src_path)
