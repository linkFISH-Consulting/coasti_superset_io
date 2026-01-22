# access_token
import requests
import typer

from .api import SuperSetApiClient, Session


app = typer.Typer()


@app.command()
def main(
    username: str = "admin",
    password: str = "admin",
    base_url: str = "http://localhost:8088",
):
    # Auth flow to get tokens for api
    token = requests.post(
        f"{base_url}/api/v1/security/login",
        headers={"Content-Type": "application/json"},
        json={
            "username": username,
            "password": password,
            "provider": "db",
            "refresh": True,
        },
    )

    # Get crfs token
    csrf = requests.get(
        f"{base_url}/api/v1/security/csrf_token",
        headers={
            "Authorization": f"Bearer {token.json().get('access_token')}",
        },
    )

    # Create api Client
    api_client = SuperSetApiClient(
        session=Session(
            base_url=base_url,
            access_token=token.json().get("access_token"),
            csrf_token=csrf.json().get("result"),
        ),
    )

    print(api_client.get_dashboards())
