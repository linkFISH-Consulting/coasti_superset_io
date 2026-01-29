from __future__ import annotations

import json
from typing import Self

import requests


class SupersetApiSession(requests.Session):
    base_url: str
    access_token: str
    csrf_token: str

    def __init__(
        self,
        access_token: str,
        csrf_token: str,
        base_url: str,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.base_url = base_url

        # Set initial headers
        self.headers.update(
            {
                "User-Agent": "coasti-superset-import-export/1.0.0",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
                "X-CSRFToken": csrf_token,
            }
        )

    def request(self, method: str | bytes, url: str | bytes, *args, **kwargs):
        # Prepend base_url if not already present
        if isinstance(url, str) and not url.startswith("http"):
            url = f"{self.base_url}{url}"
        return super().request(method, url, *args, **kwargs)

    @classmethod
    def from_credentials(
        cls,
        base_url: str,
        username: str,
        password: str,
    ) -> Self:
        """Authenticate and return an authenticated SupersetApiSession."""
        # Obtain bearer token
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
        access_token = res.json().get("access_token")

        return cls.from_token(
            base_url=base_url,
            access_token=access_token,
        )

    @classmethod
    def from_token(
        cls,
        base_url: str,
        access_token: str,
    ) -> Self:
        """Create a SupersetApiSession from an existing access token."""
        # Obtain CSRF token
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

        return cls(
            base_url=base_url,
            access_token=access_token,
            csrf_token=csrf_token,
        )


class SuperSetApiClient:
    session: SupersetApiSession

    def __init__(self, session: SupersetApiSession):
        self.session = session

    def get_dashboard(self, dashboard_id: int):
        url = f"{self.session.base_url}/dashboard/{dashboard_id}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def get_dashboards(self):
        url = f"{self.session.base_url}/api/v1/dashboard/"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def export_dashboard(self, dashboard_id: int):
        url = f"{self.session.base_url}/api/v1/dashboard/export/"
        response = self.session.get(url, params={"q": [dashboard_id]})
        response.raise_for_status()
        return response.content

    def import_dashboard(
        self,
        dashboard_data: bytes,
        overwrite: bool = False,
        passwords: dict[str, str] | None = None,
        ssh_tunnel_passwords: dict[str, str] | None = None,
        ssh_tunnel_private_key_passwords: dict[str, str] | None = None,
        ssh_tunnel_private_keys: dict[str, str] | None = None,
    ):
        # TODO: Might need some tweaking
        url = f"{self.session.base_url}/api/v1/dashboard/import/"

        # Prepare form data
        data = {}
        if overwrite:
            data["overwrite"] = "true"
        if passwords:
            data["passwords"] = json.dumps(passwords)
        if ssh_tunnel_passwords:
            data["ssh_tunnel_passwords"] = json.dumps(ssh_tunnel_passwords)
        if ssh_tunnel_private_key_passwords:
            data["ssh_tunnel_private_key_passwords"] = json.dumps(
                ssh_tunnel_private_key_passwords
            )
        if ssh_tunnel_private_keys:
            data["ssh_tunnel_private_keys"] = json.dumps(ssh_tunnel_private_keys)

        # Prepare file upload
        files = {"file": ("dashboard.json", dashboard_data, "application/json")}

        response = self.session.post(url, data=data, files=files)
        response.raise_for_status()
        return response.json()
