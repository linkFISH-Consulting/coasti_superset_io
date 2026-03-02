"""
Integration tests for dashboard export and import functionality.
"""

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
