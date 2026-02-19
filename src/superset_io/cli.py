# access_token
import logging
import os
import shutil
from pathlib import Path
from typing import Annotated, cast

import typer
from dotenv import load_dotenv

from superset_io.utils import get_version

from .api import SuperSetApiClient, SupersetApiSession

log = logging.getLogger("superset_io")
logging.basicConfig(level="INFO")
superset_api: SuperSetApiClient | None = None


app = typer.Typer()


@app.callback()
def main(
    base_url: Annotated[
        str | None, typer.Option(help="Default: from env var $SUPERSET_BASE_URL")
    ] = None,
    username: Annotated[
        str | None, typer.Option(help="Default: from env var $SUPERSET_USER")
    ] = None,
    password: Annotated[
        str | None,
        typer.Option(
            help="Default: from env var $SUPERSET_PASSWORD_FILE", hide_input=True
        ),
    ] = None,
    access_token: Annotated[
        str | None,
        typer.Option(
            help="Default: from env var $SUPERSET_ACCESS_TOKEN", hide_input=True
        ),
    ] = None,
):
    """
    Superset-IO — Automate import and export of content via superset's REST API
    """
    load_dotenv()
    authenticate(
        base_url,
        username,
        password,
        access_token,
    )


def authenticate(
    base_url: str | None = None,
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
        return

    if base_url is None:
        base_url = os.environ.get("SUPERSET_BASE_URL") or typer.prompt(
            "Base URL", type=str, default="http://localhost:8088"
        )
        base_url = cast(str, base_url)

    if access_token is None:
        access_token = os.environ.get("SUPERSET_ACCESS_TOKEN", None)
    if access_token is None:
        if username is None:
            username = os.environ.get("SUPERSET_USER") or typer.prompt(
                "Username", type=str
            )
            username = cast(str, username)

        if password is None:
            password = os.environ.get("SUPERSET_PASSWORD")
        if password is None and (
            password_file := os.environ.get("SUPERSET_PASSWORD_FILE", "")
        ):
            password = Path(password_file).read_text().rstrip()
        if password is None:
            password = typer.prompt("Password", type=str, hide_input=True)
            password = cast(str, password)

        log.debug("Acquiring access token")
        session = SupersetApiSession.from_credentials(
            base_url=base_url,
            username=username,
            password=password,
        )
    else:
        log.debug("Using provided access token")
        session = SupersetApiSession.from_token(
            base_url=base_url,
            bearer_token=access_token,
        )

    superset_api = SuperSetApiClient(session)


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
    """Test the connection to your superset instance."""

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
    superset_api.download_assets(dst_path)


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
    superset_api.upload_assets(src_path)
