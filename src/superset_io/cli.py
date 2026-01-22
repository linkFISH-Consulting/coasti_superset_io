# access_token
import logging
from typing import cast

import requests
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

        if password is None:
            password = typer.prompt("Password", type=str, hide_input=True)

        log.info("Accquiring access token")

        # bearer token
        res = requests.post(
            f"{base_url}/api/v1/security/login",
            headers={"Content-Type": "application/json"},
            json={
                "username": username,
                "password": password,
                "provider": "db",
                "refresh": False,
            },
            verify=True,
        )

        res.raise_for_status()
        access_token = cast(str, res.json().get("access_token"))
        log.debug("Obtained bearer token")

    # csrf
    res = requests.get(
        f"{base_url}/api/v1/security/csrf_token",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        verify=True,
    )
    res.raise_for_status()
    csrf_token = res.json().get("result")

    session = SupersetApiSession(
        base_url=base_url,
        access_token=access_token,
        csrf_token=csrf_token,
    )
    superset_api = SuperSetApiClient(session)


@app.command()
def main(
):
    return 0
