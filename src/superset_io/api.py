from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
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
        self.access_token = access_token
        self.csrf_token = csrf_token

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL for cookie setting."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.hostname or ""

    def request(self, method: str | bytes, url: str | bytes, *args, **kwargs):
        # Prepend base_url if not already present
        if isinstance(url, str) and not url.startswith("http"):
            url = f"{self.base_url}{url}"

        # Headers might be
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

    def export_dashboard(self, dashboard_id: int) -> zipfile.ZipFile:
        url = f"{self.session.base_url}/api/v1/dashboard/export"
        response = self.session.get(
            url,
            params={"q": json.dumps([dashboard_id])},
        )
        response.raise_for_status()

        # if the zip gets big we might need to consider streaming
        zip_content = io.BytesIO(response.content)
        return zipfile.ZipFile(zip_content, "r")

    def import_dashboard(
        self,
        zipfile_buffer: io.BytesIO | Path | bytes,
        overwrite: bool = False,
        passwords: dict[str, str] | None = None,
        ssh_tunnel_passwords: dict[str, str] | None = None,
        ssh_tunnel_private_key_passwords: dict[str, str] | None = None,
        ssh_tunnel_private_keys: dict[str, str] | None = None,
    ):
        url = f"{self.session.base_url}/api/v1/dashboard/import/"

        # Get the zip content
        if isinstance(zipfile_buffer, io.BytesIO):
            zip_content = zipfile_buffer.getvalue()
        elif isinstance(zipfile_buffer, Path):
            zip_content = zipfile_buffer.read_bytes()
        elif isinstance(zipfile_buffer, bytes):
            zip_content = zipfile_buffer
        else:
            raise ValueError("zipfile must be io.BytesIO, Path, or bytes")

        # Build multipart form data with MultipartEncoder

        # Build fields in EXACT order as working request
        fields = [
            (
                "formData",
                (
                    "dashboard_export_20260129T133411.zip",
                    zip_content,
                    "application/zip",
                ),
            ),
            ("passwords", json.dumps(passwords) if passwords else "{}"),
        ]

        if overwrite:
            fields.append(("overwrite", "true"))

        fields.extend(
            [
                (
                    "ssh_tunnel_passwords",
                    json.dumps(ssh_tunnel_passwords) if ssh_tunnel_passwords else "{}",
                ),
                (
                    "ssh_tunnel_private_keys",
                    json.dumps(ssh_tunnel_private_keys)
                    if ssh_tunnel_private_keys
                    else "{}",
                ),
                (
                    "ssh_tunnel_private_key_passwords",
                    json.dumps(ssh_tunnel_private_key_passwords)
                    if ssh_tunnel_private_key_passwords
                    else "{}",
                ),
            ]
        )

        # Convert to dict for MultipartEncoder
        fields_dict = dict(fields)

        response = self.session.post(
            url,
            files=fields_dict,
            headers={**self.session.headers, "Content-Type": "multipart/form-data"},
        )
        response.raise_for_status()
        return response
