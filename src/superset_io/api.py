from __future__ import annotations

import io
import json
import logging
import shutil
import tempfile
import zipfile
from pathlib import Path

import requests

from superset_io.session import SupersetApiSession
from superset_io.utils import (
    validate_assets_bundle_structure,
    zipfile_buffer_from_folder,
    zipfile_buffer_from_zipfile,
)

log = logging.getLogger("superset_io")


class SuperSetApiClient:
    session: SupersetApiSession

    def __init__(self, session: SupersetApiSession):
        self.session = session

    # ---------------------------- Public Methods ---------------------------- #

    def test_connection(self) -> bool:
        """Test connection is possible.

        Smoke test that:
        0) We can connect via /health
        1) Bearer auth is accepted (GET /api/v1/log/)
        2) CSRF token header is accepted (POST /api/v1/assets/import/)

        Returns true if accessible returns false if not
        """

        # 0) Server reachable
        res = self.session.get("/health")
        try:
            res.raise_for_status()
            log.info("✅ Server is reachable.")
        except requests.HTTPError as e:
            log.error(f"❌ Server not reachable: {e}")
            log.debug(f"  {e.response.text}" if e.response else "")
            return False

        # 1) Access token works
        res = self.session.get("/api/v1/log/")
        try:
            res.raise_for_status()
            log.info("✅ Access token working, can download assets.")
        except requests.HTTPError as e:
            msg = "❌ Could not access API that requires bearer token"
            if res.status_code == 401:
                msg += (
                    ". Check credentials and JWT_ALGORITHM in your superset_config.py"
                )
            log.error(f"{msg}\n  {e}")
            return False

        # 2) CSRF works: pick a POST endpoint that requires CSRF,
        # Send invalid payload so we don't create anything.
        # Expectation:
        #   - If CSRF is missing/invalid => typically 400/403 (CSRF-related)
        #   - If CSRF is accepted       => typically 400/422 (payload validation) or 403
        if not self.session.headers.get("X-CSRFToken"):
            log.error(
                "❌ No X-CSRFToken set on session; cannot validate CSRF handling."
            )
            return False

        res = self.session.post(
            "/api/v1/assets/import/",
            json={},  # invalid; we only want to get past CSRF
            headers={"Referer": self.session.base_url.rstrip("/") + "/"},
        )

        try:
            # Anything else is unexpected
            res.raise_for_status()
            log.info("✅ CSRF token working, can upload assets.")
        except requests.HTTPError as e:
            try:
                error = res.json()["errors"][0]["error_type"]
                if error == "INVALID_PAYLOAD_FORMAT_ERROR":
                    log.info("✅ CSRF token working, can upload assets.")
                else:
                    raise ValueError("Expected INVALID_PAYLOAD_FORMAT_ERROR error!")
            except Exception:
                log.error(f"❌ CSRF validation failed: {e} {res.text}")
                return False

        return True

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
