"""
Integration tests for dashboard export and import functionality.
"""

from pathlib import Path

import pytest

from superset_io.api import SupersetApiClient


@pytest.mark.integration
class TestApiClient:
    """Integration tests for dashboard export and import."""

    def test_get_dashboards(self, superset_client: SupersetApiClient):
        """Test that we can retrieve the list of dashboards."""
        dashboards = superset_client.dashboards.get_all()
        assert isinstance(dashboards, dict)
        # The response should have a 'result' key with dashboard list
        assert "result" in dashboards
        assert isinstance(dashboards["result"], list)

    def test_io_roundtrip(self, tmp_path, superset_client: SupersetApiClient):
        """Test upload of valid assets."""

        # Upload folder
        superset_client.assets.upload(
            Path(__file__).parent.parent / "assets" / "sample_assets"
        )

        # All assets should now be available
        dashboards = superset_client.dashboards.get_all()
        uuids: map[str] = map(lambda x: x["uuid"], dashboards["result"])
        assert "32fc72fd-e40c-453e-97d7-594baced4762" in uuids

        # Download folder
        superset_client.assets.download(tmp_path)

        # The uploaded dashboard should be included in the downloaded
        # assets
        assert (tmp_path / "dashboards" / "Test_Dash_1.yaml").exists()
