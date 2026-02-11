from __future__ import annotations

import base64
import io
import json
import re
import zipfile
import logging
from pathlib import Path
from typing import Self

import requests

log = logging.getLogger("superset_io")


class SupersetApiSession(requests.Session):
    base_url: str
    bearer_token: str | None
    csrf_token: str | None

    def __init__(
        self,
        base_url: str,
        bearer_token: str | None = None,
        csrf_token: str | None = None,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.base_url = base_url
        self.bearer_token = bearer_token
        self.csrf_token = csrf_token

        headers = {
            "User-Agent": "coasti-superset-import-export/1.0.0"
        }
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        if csrf_token:
            headers["X-CSRFToken"] = csrf_token

        self.headers.update(headers)

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL for cookie setting."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.hostname or ""

    def request(self, method: str | bytes, url: str | bytes, *args, **kwargs):
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
        session = cls(base_url=base_url)

        bearer_token = session._get_bearer_token(username, password)
        session.bearer_token = bearer_token
        session.headers["Authorization"] = f"Bearer {bearer_token}"

        # quick validation, some endpoints dont need csrf.
        # no need to continue if this fails already
        res = session.get("/api/v1/dashboard/")
        res.raise_for_status()

        try:
            session = cls.from_token(base_url, bearer_token, session=session)
        except RuntimeError as e:
            # this is our custom error for jwt config errors on server
            log.error(e)
            session._get_csrf_via_session_cookie(username, password)

        return session

    @classmethod
    def from_token(
        cls,
        base_url: str,
        bearer_token: str,
        session: Self | None = None,
    ) -> Self:
        """Create a SupersetApiSession from an existing access token."""

        if session is None:
            session = cls(base_url=base_url, bearer_token=bearer_token)

        # get csrf for api writes
        csrf_token = session._get_csrf_via_bearer()
        session.csrf_token = csrf_token
        session.headers["X-CSRFToken"] = csrf_token
        return session

    def _get_bearer_token(self, username: str, password: str) -> str:
        """Get a bearer access token"""
        log.debug("Obtaining bearer access token")
        res = self.post(
            "/api/v1/security/login",
            headers={"Content-Type": "application/json"},
            json={
                "username": username,
                "password": password,
                "provider": "db",
                "refresh": False,
            },
            verify=True,
        )

        try:
            res.raise_for_status()
        except:
            log.error(res.text)
            raise

        token = res.json().get("access_token")
        log.debug(f"access token algorithm {self._jwt_header(token)}")

        return token

    def _get_csrf_via_bearer(self) -> str:
        log.debug("Obtaining csrf token via bearer")
        res = self.get("/api/v1/security/csrf_token/")
        if not res.ok:
            if (
                res.status_code == 422
                and "The specified alg value is not allowed" in res.text
            ):
                raise RuntimeError(
                    "Superset rejected the Bearer JWT: "
                    f"{self._jwt_header(str(self.bearer_token))}."
                    "Fix server config (e.g., JWT_ALGORITHM/allowed algorithms) "
                    "or use cookie/session auth."
                )

            try:
                res.raise_for_status()
            except:
                log.error(res.text)
                raise

        return res.json()["result"]

    def _get_csrf_via_session_cookie(self, username: str, password: str) -> None:
        """
        Try to get a working csrf token via login page and session cookie.

        TODO: Verify, and this will likely be the path for keycloak.
        """

        log.debug("Obtaining csrf token via session cookie")
        res = self.get("/login/")
        res.raise_for_status()

        match = re.search(
            r'name="csrf_token"\s+type="hidden"\s+value="([^"]+)"', res.text
        )
        if match:
            csrf = match.group(1)
        else:
            raise RuntimeError(
                "Could not find csrf_token field on /login/ page. "
                "Cookie-based login fallback may not be supported/enabled."
            )

        # POST login form (Flask-AppBuilder default fields)
        res = self.post(
            "/login/",
            data={
                "username": username,
                "password": password,
                "csrf_token": csrf,
            },
            allow_redirects=True,
            headers={"Accept": "text/html,application/xhtml+xml"},
        )
        res.raise_for_status()

        res = self.get("/api/v1/security/csrf_token/")
        res.raise_for_status()
        csrf = res.json()["result"]  # TODO: Check, is this the same csrf as before?

        self.headers["X-CSRFToken"] = csrf
        self.csrf_token = csrf

    @classmethod
    def _jwt_header(cls, token: str) -> dict:
        header_b64 = token.split(".")[0]
        header_b64 += "=" * (-len(header_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(header_b64).decode("utf-8"))

    @classmethod
    def _extract_csrf_from_login_html(cls, html: str) -> str | None:
        """
        Superset's /login/ page typically includes a CSRF token in a hidden input
        called "csrf_token". This is not guaranteed across all themes/versions,
        but works in many default deployments.

        PS: not verified.
        """

        return None


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

        # Get the zip content
        if isinstance(zipfile_buffer, io.BytesIO):
            zip_content = zipfile_buffer.getvalue()
        elif isinstance(zipfile_buffer, Path):
            zip_content = zipfile_buffer.read_bytes()
        elif isinstance(zipfile_buffer, bytes):
            zip_content = zipfile_buffer
        else:
            raise ValueError("zipfile must be io.BytesIO, Path, or bytes")

        # print layout of the created zip_content
        with zipfile.ZipFile(io.BytesIO(zip_content)) as zf:
            log.info("ZIP file contents:")
            for info in zf.infolist():
                log.info(f"  {info.filename}  ({info.file_size} bytes)")

        # IMPORTANT: only the file goes into `files=`
        multipart_files = {
            "bundle": (
                "dashboard_export.zip",
                zip_content,
                "application/zip",
            )
        }

        # IMPORTANT: all non-file fields go into `data=`
        form_data = {
            "passwords": json.dumps(passwords or {}),
            "ssh_tunnel_passwords": json.dumps(ssh_tunnel_passwords or {}),
            "ssh_tunnel_private_keys": json.dumps(ssh_tunnel_private_keys or {}),
            "ssh_tunnel_private_key_passwords": json.dumps(
                ssh_tunnel_private_key_passwords or {}
            ),
        }
        if overwrite:
            form_data["overwrite"] = "true"

        # IMPORTANT: ensure JSON content-type is NOT sent
        headers = dict(self.session.headers)
        headers.pop("Content-Type", None)

        log.info(headers)

        res = self.session.post(
            "/api/v1/assets/import/",
            files=multipart_files,
            data=form_data,
            headers=headers,
        )

        # helpful for debugging:
        # import http.client as http_client
        # http_client.HTTPConnection.debuglevel = 1
        # logging.basicConfig(level=logging.DEBUG)
        # logging.getLogger("urllib3").setLevel(logging.DEBUG)
        # logging.getLogger("urllib3").propagate = True

        print(res.text)
        print(res.json())
        print(res.request.headers.get("Content-Type"))

        try:
            res.raise_for_status()
        except:
            log.error(res.text)

        return res


