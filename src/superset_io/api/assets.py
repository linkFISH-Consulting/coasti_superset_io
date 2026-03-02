import io
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from superset_io.utils import (
    validate_assets_bundle_structure,
    zipfile_buffer_from_folder,
    zipfile_buffer_from_zipfile,
)

from .abc import ClientBase


class AssetsApiClient(ClientBase):
    # See also https://superset.apache.org/developer-docs/api/export-all-assets

    def _import(
        self,
        zipfile_buffer: io.BytesIO | Path | bytes,
        overwrite: bool = False,
        passwords: dict[str, str] | None = None,
        ssh_tunnel_passwords: dict[str, str] | None = None,
        ssh_tunnel_private_key_passwords: dict[str, str] | None = None,
        ssh_tunnel_private_keys: dict[str, str] | None = None,
        sparse: bool = False,
    ):
        """Import multiple assets"""

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
            "sparse": sparse,
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

    def _export(self):
        """Gets a ZIP file with all the Superset assets.

        Includes databases, datasets, charts, dashboards, saved queries
        as YAML files.
        """
        url = f"{self.session.base_url}/api/v1/assets/export"
        res = self.session.get(url)
        res.raise_for_status()
        return res

    def upload(self, src_path: Path):
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

        self._import(zipfile_buffer=zipfile_buffer)

    def download(self, dst_path: Path):
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

        res = self._export()
        # if the zip gets big we might need to consider streaming
        zip_bytes = res.content
        zip_file = zipfile.ZipFile(io.BytesIO(zip_bytes), "r")

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
