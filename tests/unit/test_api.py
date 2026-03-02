"""
Unit tests for the Superset API client.
"""

import io
import zipfile
from unittest.mock import Mock

import pytest
import requests

from superset_io.api import SuperSetApiClient


def _resp(*, status_code=200, text="", json_data=None, raise_exc=None):
    r = Mock()
    r.status_code = status_code
    r.text = text
    r.json = Mock(return_value=json_data if json_data is not None else {})
    if raise_exc is None:
        r.raise_for_status = Mock()
    else:
        r.raise_for_status = Mock(side_effect=raise_exc)
    return r


def _http_error(msg="http error", *, response_text=""):
    err = requests.HTTPError(msg)
    if response_text:
        err.response = Mock()
        err.response.text = response_text
    return err


class TestAPITestConnection:
    """Lean unit tests for request-building logic in SuperSetApiClient."""

    def test_connection_health_fails(self):
        session = Mock()
        session.base_url = "http://localhost:8088"
        session.headers = {"X-CSRFToken": "csrf"}  # shouldn't matter; should exit early

        session.get = Mock(
            side_effect=[
                _resp(raise_exc=_http_error("health down", response_text="nope"))
            ]
        )
        session.post = Mock()

        client = SuperSetApiClient(session)
        assert client.test_connection() is False

        session.get.assert_called_once_with("/health")
        session.post.assert_not_called()

    def test_connection_log_fails(self):
        session = Mock()
        session.base_url = "http://localhost:8088"
        session.headers = {"X-CSRFToken": "csrf"}

        session.get = Mock(
            side_effect=[
                _resp(),  # /health ok
                _resp(
                    status_code=401, raise_exc=_http_error("unauthorized")
                ),  # /api/v1/log/ fails
            ]
        )
        session.post = Mock()

        client = SuperSetApiClient(session)
        assert client.test_connection() is False

        assert session.get.call_args_list[0].args[0] == "/health"
        assert session.get.call_args_list[1].args[0] == "/api/v1/log/"
        session.post.assert_not_called()

    def test_connection_missing_csrf_header(self):
        session = Mock()
        session.base_url = "http://localhost:8088"
        session.headers = {}  # no X-CSRFToken

        session.get = Mock(side_effect=[_resp(), _resp()])
        session.post = Mock()

        client = SuperSetApiClient(session)
        assert client.test_connection() is False

        session.post.assert_not_called()

    def test_connection_succeeds_with_invalid_payload(self):
        session = Mock()
        session.base_url = "http://localhost:8088/"
        session.headers = {"X-CSRFToken": "csrf"}

        session.get = Mock(side_effect=[_resp(), _resp()])

        post_res = _resp(
            status_code=422,
            text="unprocessable entity",
            json_data={"errors": [{"error_type": "INVALID_PAYLOAD_FORMAT_ERROR"}]},
            raise_exc=_http_error("422"),
        )
        session.post = Mock(return_value=post_res)

        client = SuperSetApiClient(session)
        assert client.test_connection() is True

    def test_connection_error_type_not_expected(self):
        """
        This covers the 'POST fails and JSON doesn't match heuristic' => should return
        False.
        """
        session = Mock()
        session.base_url = "http://localhost:8088"
        session.headers = {"X-CSRFToken": "csrf"}

        session.get = Mock(side_effect=[_resp(), _resp()])

        post_res = _resp(
            status_code=403,
            text="forbidden",
            json_data={"errors": [{"error_type": "SOME_OTHER_ERROR"}]},
            raise_exc=_http_error("403"),
        )
        session.post = Mock(return_value=post_res)

        client = SuperSetApiClient(session)

        # If your current code has the `e` NameError, this will raise.
        # Once code is fixed, it should simply be False.

        assert client.test_connection() is False

    def test_connection_post_succeeds(self):
        session = Mock()
        session.base_url = "http://localhost:8088"
        session.headers = {"X-CSRFToken": "csrf"}

        session.get = Mock(side_effect=[_resp(), _resp()])
        session.post = Mock(return_value=_resp(status_code=200))

        client = SuperSetApiClient(session)
        assert client.test_connection() is True

        session.post.assert_called_once_with(
            "/api/v1/assets/import/",
            json={},
            headers={"Referer": "http://localhost:8088/"},
        )


class TestUploadAssets:
    @pytest.fixture
    def asset_folder(self, tmp_path):
        assets_root = tmp_path / "assets_folder"
        (assets_root / "dashboards").mkdir(parents=True)

        (assets_root / "metadata.yaml").write_text("version: 1.0", encoding="utf-8")
        (assets_root / "dashboards" / "demo.yaml").write_text(
            "dashboard_title: Demo", encoding="utf-8"
        )
        yield assets_root

    @pytest.fixture
    def client(self):
        session = Mock()
        session.base_url = "http://localhost:8088"
        session.headers = {"X-CSRFToken": "csrf"}
        return SuperSetApiClient(session)

    def test_upload_assets_zip(self, tmp_path, asset_folder, client, monkeypatch):
        # Create a real zip on disk from the fixture folder contents
        zip_path = tmp_path / "assets_bundle.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for p in asset_folder.rglob("*"):
                if p.is_file():
                    zf.write(p, arcname=p.relative_to(asset_folder.parent).as_posix())

        post_mock = Mock()
        monkeypatch.setattr(client, "_post_assets", post_mock)

        client.upload_assets(zip_path)

        post_mock.assert_called_once()
        buf = post_mock.call_args.kwargs["zipfile_buffer"]

        assert isinstance(buf, io.BytesIO)
        assert buf.getvalue() == zip_path.read_bytes()

    def test_upload_assets_folder(self, asset_folder, client, monkeypatch):
        post_mock = Mock()
        monkeypatch.setattr(client, "_post_assets", post_mock)

        client.upload_assets(asset_folder)

        post_mock.assert_called_once()
        buf = post_mock.call_args.kwargs["zipfile_buffer"]

        assert isinstance(buf, io.BytesIO)
        # ensure zipped structure contains expected files
        with zipfile.ZipFile(buf, "r") as zf:
            names = zf.namelist()
            assert "assets_folder/metadata.yaml" in names
            assert "assets_folder/dashboards/demo.yaml" in names
