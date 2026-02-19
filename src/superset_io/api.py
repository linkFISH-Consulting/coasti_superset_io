from __future__ import annotations

import base64
import io
import json
import logging
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Self, cast

import requests

from superset_io.utils import (
    validate_assets_bundle_structure,
    zipfile_buffer_from_folder,
    zipfile_buffer_from_zipfile,
)

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

        headers = {"User-Agent": "coasti-superset-import-export/1.0.0"}
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

        try:
            bearer_token = session._get_bearer_token(username, password)
            session.bearer_token = bearer_token
            session.headers["Authorization"] = f"Bearer {bearer_token}"
        except requests.HTTPError:
            log.debug("Failed to get bearer token")
            bearer_token = cast(str, None)
            # Some features work without authentication, in particular connection test.
            # A bit dirty, we should not pass None to `from_token`, but I do not want
            # to change the type hint of the public classmethod.

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
        try:
            csrf_token = session._get_csrf_via_bearer()
            session.csrf_token = csrf_token
            session.headers["X-CSRFToken"] = csrf_token
        except requests.HTTPError:
            log.debug("Failed to get csrf token")
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

        res.raise_for_status()

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

            res.raise_for_status()

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

    # ---------------------------- Public Methods ---------------------------- #

    def test_connection(self) -> bool:
        """
        Smoke test that:
        0) We can connect via /health
        1) Bearer auth is accepted (GET /api/v1/log/)
        2) CSRF token header is accepted (POST /api/v1/assets/import/)

        Raises requests.HTTPError on unexpected failures.
        """

        # 0) Server reachable
        res = self.session.get("/health")
        try:
            res.raise_for_status()
            log.info("✅ Server is reachable.")
        except Exception as e:
            log.error(f"❌ Server not reachable: {e}")

        # 1) Access token works
        res = self.session.get("/api/v1/log/")
        try:
            res.raise_for_status()
            log.info("✅ Access token working, can download assets.")
        except Exception as e:
            msg = "❌ Could not access API that requires bearer token"
            if res.status_code == 401:
                msg += (
                    ". Check credentials and JWT_ALGORITHM in your superset_config.py"
                )
            log.error(f"{msg}\n  {e}")

        # 2) CSRF works: pick a POST endpoint that requires CSRF,
        # Send invalid payload so we don't create anything.
        # Expectation:
        #   - If CSRF is missing/invalid => typically 400/403 (CSRF-related)
        #   - If CSRF is accepted       => typically 400/422 (payload validation) or 403
        if not self.session.headers.get("X-CSRFToken"):
            log.error(
                "❌ No X-CSRFToken set on session; cannot validate CSRF handling."
            )
        else:
            res = self.session.post(
                "/api/v1/assets/import/",
                json={},  # invalid; we only want to get past CSRF
                headers={
                    "Referer": self.session.base_url.rstrip("/") + "/"
                }
            )

            if res.status_code in (400, 401, 403, 422):
                # Heuristic: distinguish "blocked by CSRF" vs
                # "passed CSRF but failed validation/permission"
                body = (res.text or "").lower()
                if "csrf" in body:
                    log.error(
                        f"❌  CSRF appears to be rejected: {res.status_code} {res.text}"
                    )
                try:
                    error = res.json()["errors"][0]["error_type"]
                    if error == "INVALID_PAYLOAD_FORMAT_ERROR":
                        log.info("✅ CSRF token working, can upload assets.")
                        return True
                except Exception:
                    pass

            try:
                # Anything else is unexpected
                res.raise_for_status()
                log.info("✅ CSRF token working, can upload assets.")
                return True
            except Exception as e:
                log.error(f"❌ CSRF validation failed: {e} {res.text}")

        return False

    def download_assets(self, dst_path: Path):
        """Download and export all assets to disk.

        Depending an provided dst_path, we either write as zip file or the extracted
        folder structure.
        """

        if dst_path.suffix.lower() == ".zip":
            kind = "zip"
        else:
            kind = "folder"
            dst_path.mkdir(parents=True, exist_ok=True)

        if kind == "folder" and any(dst_path.iterdir()):
            raise ValueError(f"Destination directory '{dst_path}' is not empty")

        zip_bytes, zip_file = self._get_assets_zip()

        if kind == "zip":
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            with dst_path.open("wb") as f:
                f.write(zip_bytes)
        else:
            # Extract to temp dir, get the assets and move to dst_path
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                zip_file.extractall(tmp_path)

                src_folders = [
                    f for f in tmp_path.iterdir() if f.name.startswith("assets_export")
                ]
                if len(src_folders) != 1:
                    raise ValueError(
                        "Did not find a single `assets_export` folder in zip. "
                        "This should not happen."
                    )

                for item in src_folders[0].iterdir():
                    shutil.move(item, dst_path / item.name)

    def upload_assets(self, src_path: Path):
        """Upload and restore assets from disk.

        src_path can be zip or directory.
        If directory, needs to directly contain the metadata.yml.
        """

        if src_path.suffix.lower() == ".zip":
            zipfile_buffer = zipfile_buffer_from_zipfile(src_path)
        else:
            zipfile_buffer = zipfile_buffer_from_folder(src_path)

        # raise for invalid zips, already before trying the endpoint
        validate_assets_bundle_structure(zipfile_buffer)

        self._post_assets(zipfile_buffer=zipfile_buffer)

    # ----------------------------- Internal Use ----------------------------- #

    def _get_dashboard(self, dashboard_id: int):
        """Get a single dashboard.

        For actual downloading, better use more modern assets api."""
        url = f"{self.session.base_url}/dashboard/{dashboard_id}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def _get_dashboards(self):
        """Get overview all dashboards.

        For actual downloading, better use more modern assets api."""
        url = f"{self.session.base_url}/api/v1/dashboard/"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def _get_assets_zip(self):
        """Get all assets from server as zip."""
        url = f"{self.session.base_url}/api/v1/assets/export"
        response = self.session.get(url)
        response.raise_for_status()

        # if the zip gets big we might need to consider streaming
        zip_bytes = response.content
        return zip_bytes, zipfile.ZipFile(io.BytesIO(zip_bytes), "r")

    def _post_assets(
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

        # only the file goes into `files=`
        files = {
            "bundle": (
                "name_does_not_matter.zip",
                zip_content,
                "application/zip",
            )
        }

        # all non-file fields go into `data=`
        data = {
            "passwords": json.dumps(passwords or {}),
            "ssh_tunnel_passwords": json.dumps(ssh_tunnel_passwords or {}),
            "ssh_tunnel_private_keys": json.dumps(ssh_tunnel_private_keys or {}),
            "ssh_tunnel_private_key_passwords": json.dumps(
                ssh_tunnel_private_key_passwords or {}
            ),
        }
        if overwrite:
            data["overwrite"] = "true"

        # ensure content-type is not set, to allow requests.post to set it.
        # this is needed so the boundary (file length) is also set automatically
        headers = dict(self.session.headers)
        headers.pop("Content-Type", None)
        headers["Referer"] = self.session.base_url.rstrip("/") + "/"

        res = self.session.post(
            "/api/v1/assets/import/",
            files=files,
            data=data,
            headers=headers,
        )

        res.raise_for_status()

        return res
