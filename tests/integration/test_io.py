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


@pytest.mark.integration
class TestDashboardEndpoints:
    @pytest.fixture(autouse=True)
    def seed_db(self, superset_client: SupersetApiClient):
        """Seed the database with a sample dashboard before each test."""
        # Upload the sample dashboard
        superset_client.assets.upload(
            Path(__file__).parent.parent / "assets" / "sample_assets"
        )

    @pytest.fixture
    def dashboard_uuid(self) -> str:
        """Return the UUID of the sample dashboard."""
        return "32fc72fd-e40c-453e-97d7-594baced4762"

    @pytest.fixture
    def chart_uuid(self) -> str:
        """Return the UUID of the sample chart."""
        return "af8b8462-416f-480f-bbdf-abb068e1c400"

    def test_get(
        self,
        superset_client: SupersetApiClient,
        dashboard_uuid: str,
    ) -> None:
        """Test that we can retrieve the sample dashboard."""
        dashboard = superset_client.dashboards.get(dashboard_uuid)
        assert dashboard is not None
        assert dashboard["result"]["uuid"] == dashboard_uuid

    def test_remove(
        self, superset_client: SupersetApiClient, dashboard_uuid: str, chart_uuid: str
    ) -> None:
        """Test that we can delete the sample dashboard."""
        superset_client.dashboards.remove(dashboard_uuid)

        # Attempting to retrieve the deleted dashboard should now fail
        with pytest.raises(Exception):
            superset_client.dashboards.get(dashboard_uuid)

        # This does not delete the underlying assets!
        charts = superset_client.charts.get(chart_uuid)
        assert charts is not None

    def test_get_all(self, superset_client: SupersetApiClient) -> None:
        """Test that we can retrieve the list of charts."""
        charts = superset_client.dashboards.get_all()
        assert isinstance(charts, dict)
        # The response should have a 'result' key with chart list
        assert "result" in charts
        assert isinstance(charts["result"], list)


@pytest.mark.integration
class TestChartsEndpoints:
    @pytest.fixture(autouse=True)
    def seed_db(self, superset_client: SupersetApiClient):
        """Seed the database with a sample dashboard before each test."""
        # Upload the sample dashboard
        superset_client.assets.upload(
            Path(__file__).parent.parent / "assets" / "sample_assets"
        )

    @pytest.fixture
    def chart_uuid(self) -> str:
        """Return the UUID of the sample chart."""
        return "af8b8462-416f-480f-bbdf-abb068e1c400"

    def test_get(
        self,
        superset_client: SupersetApiClient,
        chart_uuid: str,
    ) -> None:
        """Test that we can retrieve the sample chart."""
        chart = superset_client.charts.get(chart_uuid)
        assert chart is not None
        assert chart["result"]["uuid"] == chart_uuid

    def test_remove(self, superset_client: SupersetApiClient, chart_uuid: str) -> None:
        """Test that we can delete the sample dashboard."""
        superset_client.charts.remove(chart_uuid)

        # Attempting to retrieve the deleted dashboard should now fail
        with pytest.raises(Exception):
            superset_client.charts.get(chart_uuid)

    def test_get_all(self, superset_client: SupersetApiClient) -> None:
        """Test that we can retrieve the list of charts."""
        charts = superset_client.charts.get_all()
        assert isinstance(charts, dict)
        # The response should have a 'result' key with chart list
        assert "result" in charts
        assert isinstance(charts["result"], list)


@pytest.mark.integration
class TestDatasetEndpoints:
    @pytest.fixture(autouse=True)
    def seed_db(self, superset_client: SupersetApiClient):
        """Seed the database with a sample dashboard before each test."""
        # Upload the sample dashboard
        superset_client.assets.upload(
            Path(__file__).parent.parent / "assets" / "sample_assets"
        )

    @pytest.fixture
    def dataset_uuid(self) -> str:
        """Return the UUID of the sample dataset."""
        return "f19609fc-0ff0-4bf3-a563-4c6e8a74b759"

    def test_get(
        self,
        superset_client: SupersetApiClient,
        dataset_uuid: str,
    ) -> None:
        """Test that we can retrieve the sample dataset."""

        # Get by uuid
        dataset = superset_client.datasets.get(dataset_uuid)
        assert dataset is not None
        assert dataset["uuid"] == dataset_uuid

        # Get same again by id
        dataset_by_id = superset_client.datasets.get(dataset["id"])
        assert dataset_by_id is not None
        assert dataset_by_id["id"] == dataset["id"]

    def test_get_all(self, superset_client: SupersetApiClient) -> None:
        """Test that we can retrieve the list of datasets."""
        datasets = superset_client.datasets.get_all()
        assert isinstance(datasets, dict)
        # The response should have a 'result' key with dataset list
        assert "result" in datasets
        assert isinstance(datasets["result"], list)

    def test_remove(
        self, superset_client: SupersetApiClient, dataset_uuid: str
    ) -> None:
        """Test that we can delete the sample dataset."""
        superset_client.datasets.remove(dataset_uuid)

        # Attempting to retrieve the deleted dataset should now fail
        with pytest.raises(Exception):
            superset_client.datasets.get(dataset_uuid)


@pytest.mark.integration
class TestDatabaseEndpoints:
    @pytest.fixture(autouse=True)
    def seed_db(self, superset_client: SupersetApiClient):
        """Seed the database with a sample dashboard before each test."""
        # Upload the sample dashboard
        superset_client.assets.upload(
            Path(__file__).parent.parent / "assets" / "sample_assets"
        )

    @pytest.fixture
    def database_uuid(self) -> str:
        """Return the UUID of the sample database."""
        return "f8a5145d-4469-43c4-b6cc-1b8a0097f3f9"

    def test_get(
        self,
        superset_client: SupersetApiClient,
        database_uuid: str,
    ) -> None:
        """Test that we can retrieve the sample database."""
        database = superset_client.databases.get(database_uuid)
        assert database is not None
        assert database["uuid"] == database_uuid

        # Get same again by id
        database_by_id = superset_client.databases.get(database["id"])
        assert database_by_id is not None
        assert database_by_id["id"] == database["id"]

    def test_get_all(self, superset_client: SupersetApiClient) -> None:
        """Test that we can retrieve the list of databases."""
        databases = superset_client.databases.get_all()
        assert isinstance(databases, dict)
        # The response should have a 'result' key with database list
        assert "result" in databases
        assert isinstance(databases["result"], list)

    def test_remove(
        self, superset_client: SupersetApiClient, database_uuid: str
    ) -> None:
        """Test that we can delete the sample database."""

        # A bit inconsistent but this only works if a no datasets are attached
        with pytest.raises(Exception, match="UNPROCESSABLE ENTITY for url"):
            superset_client.databases.remove(database_uuid)

        # Remove the attached dataset first
        dataset = superset_client.datasets.get_all()
        for ds in dataset["result"]:
            if ds["database"]["uuid"] == database_uuid:
                superset_client.datasets.remove(ds["uuid"])

        # Now we can remove the database
        superset_client.databases.remove(database_uuid)

        # Attempting to retrieve the deleted database should now fail
        with pytest.raises(Exception):
            superset_client.databases.get(database_uuid)
