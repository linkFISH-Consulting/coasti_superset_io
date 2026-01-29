# access_token
import logging
from typing import cast

import typer

from .api import SuperSetApiClient, SupersetApiSession

log = logging.getLogger("superset_io")
superset_api: SuperSetApiClient | None = None

# gets invoked via our script in pyproject.toml
app = typer.Typer()


@app.callback()
def auth(
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
        base_url = typer.prompt("Base URL", type=str, default="http://localhost:8088")
        base_url = cast(str, base_url)

    if access_token is None:
        if username is None:
            username = typer.prompt("Username", type=str)
            username = cast(str, username)

        if password is None:
            password = typer.prompt("Password", type=str, hide_input=True)
            password = cast(str, password)

        log.info("Acquiring access token")
        session = SupersetApiSession.from_credentials(
            base_url=base_url,
            username=username,
            password=password,
        )
    else:
        log.info("Using provided access token")
        session = SupersetApiSession.from_token(
            base_url=base_url,
            access_token=access_token,
        )

    superset_api = SuperSetApiClient(session)


@app.command()
def main():
    return 0
