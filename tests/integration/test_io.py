"""
Integration tests for dashboard export and import functionality.
"""

from pathlib import Path

import pytest

from superset_io.api import SuperSetApiClient


@pytest.mark.integration
class TestApiClient:
    """Integration tests for dashboard export and import."""

    def test_get_dashboards(self, superset_client: SuperSetApiClient):
        """Test that we can retrieve the list of dashboards."""
        dashboards = superset_client._get_dashboards()
        assert isinstance(dashboards, dict)
        # The response should have a 'result' key with dashboard list
        assert "result" in dashboards
        assert isinstance(dashboards["result"], list)

    def test_upload(self, superset_client: SuperSetApiClient):
        """Test upload of valid assets."""

        # Upload folder
        superset_client.upload_assets(
            Path(__file__).parent.parent / "assets" / "sample_assets"
        )

        # All dashboards should now include the new one
        dashboards = superset_client._get_dashboards()
        uuids: map[str] = map(lambda x: x["uuid"], dashboards["result"])
        assert "32fc72fd-e40c-453e-97d7-594baced4762" in uuids
