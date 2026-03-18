"""Test suite for the dependency graph submodule."""

from pathlib import Path
from uuid import UUID

import pytest

from superset_io.dependency_graph.assets import Asset, AssetType
from superset_io.dependency_graph.graph import DependencyGraph
from superset_io.dependency_graph.parser import AssetsParser


class TestAsset:
    """Tests for Asset class."""

    def test_asset_equality_by_uuid(self):
        """Asset equality should be based on UUID only."""
        uuid = UUID("12345678-1234-5678-1234-567812345678")
        asset1 = Asset(uuid=uuid, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid, type=AssetType.DASHBOARD)
        assert asset1 == asset2

    def test_asset_equality_with_string(self):
        """Asset should equal UUID string."""
        uuid_str = "12345678-1234-5678-1234-567812345678"
        uuid = UUID(uuid_str)
        asset = Asset(uuid=uuid, type=AssetType.CHART)
        assert asset == uuid_str

    def test_asset_equality_with_uuid(self):
        """Asset should equal UUID object."""
        uuid_str = "12345678-1234-5678-1234-567812345678"
        uuid = UUID(uuid_str)
        asset = Asset(uuid=uuid, type=AssetType.CHART)
        assert asset == uuid

    def test_asset_hash_stable(self):
        """Hash should be stable regardless of type."""
        uuid = UUID("12345678-1234-5678-1234-567812345678")
        asset1 = Asset(uuid=uuid, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid, type=AssetType.DASHBOARD)
        assert hash(asset1) == hash(asset2)

    def test_asset_from_string_uuid(self):
        """Asset should accept string UUID and convert to UUID."""
        uuid_str = "12345678-1234-5678-1234-567812345678"
        asset = Asset(uuid=uuid_str, type=AssetType.CHART)
        assert asset.uuid == UUID(uuid_str)

    @pytest.mark.parametrize(
        "type_enum",
        [
            AssetType.DATABASE,
            AssetType.DATASET,
            AssetType.CHART,
            AssetType.DASHBOARD,
            AssetType.THEME,
            AssetType.UNKNOWN,
        ],
    )
    def test_asset_type_values(self, type_enum):
        """All AssetType values should be valid."""
        uuid = UUID("12345678-1234-5678-1234-567812345678")
        asset = Asset(uuid=uuid, type=type_enum)
        assert asset.type == type_enum


class TestDependencyGraph:
    """Tests for DependencyGraph class."""

    def test_empty_graph(self):
        """Empty graph should have no assets."""
        graph = DependencyGraph()
        assert graph.assets == set()
        assert graph.dependents == {}
        assert graph.dependencies == {}

    def test_add_dependency_creates_nodes(self):
        """Adding dependency should create both nodes in the graph."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)

        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)
        graph.enforce_invariants()

        assert asset1 in graph.assets
        assert asset2 in graph.assets
        assert asset2 in graph.get_dependencies(asset1)
        assert asset1 in graph.get_dependent(asset2)

    def test_add_dependency_idempotent(self):
        """Adding same dependency multiple times should only create one edge."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)

        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)
        graph.add_dependency(asset1, asset2)

        assert len(graph.get_dependencies(asset1)) == 1

    def test_add_asset_bulk_merge(self):
        """add_asset should bulk merge dependencies and dependents."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        uuid3 = UUID("11111111-2222-3333-4444-555555555555")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)
        asset3 = Asset(uuid=uuid3, type=AssetType.DATABASE)

        graph = DependencyGraph()
        graph.add_asset(asset1, {asset2}, {asset3})

        assert asset2 in graph.get_dependencies(asset1)
        assert asset3 in graph.get_dependent(asset1)

    def test_enforce_invariants_creates_missing_nodes(self):
        """enforce_invariants should create missing nodes in both maps."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)

        graph = DependencyGraph()
        graph.add_asset(asset1, set(), set())
        graph.add_asset(asset2, set(), {asset1})
        assert len(graph.get_dependencies(asset1)) == 0
        graph.enforce_invariants()
        assert len(graph.get_dependencies(asset1)) == 1

        assert asset1 in graph.assets
        assert asset2 in graph.assets

    def test_assets_method(self):
        """assets() should return all nodes in the graph."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        uuid3 = UUID("11111111-2222-3333-4444-555555555555")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)
        asset3 = Asset(uuid=uuid3, type=AssetType.DATABASE)

        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)
        graph.add_dependency(asset2, asset3)

        all_assets = graph.assets
        assert asset1 in all_assets
        assert asset2 in all_assets
        assert asset3 in all_assets

    def test_assets_of_type(self):
        """assets_of_type() should filter by type."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        uuid3 = UUID("11111111-2222-3333-4444-555555555555")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)
        asset3 = Asset(uuid=uuid3, type=AssetType.DATABASE)

        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)
        graph.add_dependency(asset2, asset3)

        charts = graph.assets_of_type(AssetType.CHART)
        assert asset1 in charts
        assert asset2 not in charts
        assert asset3 not in charts

    def test_assets_of_type_multiple(self):
        """assets_of_type() should accept multiple types."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        uuid3 = UUID("11111111-2222-3333-4444-555555555555")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)
        asset3 = Asset(uuid=uuid3, type=AssetType.DATABASE)

        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)
        graph.add_dependency(asset2, asset3)

        assets = graph.assets_of_type(AssetType.CHART, AssetType.DATABASE)
        assert asset1 in assets
        assert asset2 not in assets
        assert asset3 in assets

    def test_assets_of_type_empty_returns_all(self):
        """assets_of_type() with no args should return all assets."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)

        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)

        assert graph.assets_of_type() == graph.assets

    def test_counts_by_type(self):
        """counts_by_type() should return correct counts."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        uuid3 = UUID("11111111-2222-3333-4444-555555555555")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)
        asset3 = Asset(uuid=uuid3, type=AssetType.DATABASE)

        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)
        graph.add_dependency(asset2, asset3)

        counts = graph.counts_by_type()
        assert counts[AssetType.CHART] == 1
        assert counts[AssetType.DATASET] == 1
        assert counts[AssetType.DATABASE] == 1

    def test_get_dependencies_by_uuid_string(self):
        """get_dependencies() should work with UUID string."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)

        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)

        deps = graph.get_dependencies(str(uuid1))
        assert asset2 in deps

    def test_get_dependencies_by_uuid_object(self):
        """get_dependencies() should work with UUID object."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)

        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)

        deps = graph.get_dependencies(uuid1)
        assert asset2 in deps

    def test_get_dependencies_unknown_asset(self):
        """get_dependencies() should return empty set for unknown asset."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)

        graph = DependencyGraph()
        deps = graph.get_dependencies(asset1)
        assert deps == set()

    def test_get_dependent_by_uuid_string(self):
        """get_dependent() should work with UUID string."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)

        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)

        dependents = graph.get_dependent(str(uuid2))
        assert asset1 in dependents

    def test_get_dependent_by_uuid_object(self):
        """get_dependent() should work with UUID object."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        uuid2 = UUID("87654321-4321-8765-4321-876543215678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)
        asset2 = Asset(uuid=uuid2, type=AssetType.DATASET)

        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)

        dependents = graph.get_dependent(uuid2)
        assert asset1 in dependents

    def test_get_dependent_unknown_asset(self):
        """get_dependent() should return empty set for unknown asset."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)

        graph = DependencyGraph()
        dependents = graph.get_dependent(asset1)
        assert dependents == set()

    def test_get_asset_by_uuid_string(self):
        """get_asset() should work with UUID string."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)

        graph = DependencyGraph()
        graph.add_asset(asset1, set(), set())

        found = graph.get_asset(str(uuid1))
        assert found == asset1

    def test_get_asset_by_uuid_object(self):
        """get_asset() should work with UUID object."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")
        asset1 = Asset(uuid=uuid1, type=AssetType.CHART)

        graph = DependencyGraph()
        graph.add_asset(asset1, set(), set())

        found = graph.get_asset(uuid1)
        assert found == asset1

    def test_get_asset_not_found(self):
        """get_asset() should return None for non-existent asset."""
        uuid1 = UUID("12345678-1234-5678-1234-567812345678")

        graph = DependencyGraph()
        found = graph.get_asset(uuid1)
        assert found is None


class TestAssetsParser:
    """Tests for AssetsParser class."""

    @pytest.fixture
    def parser(self, tmp_path):
        """Create parser with temp folder."""
        return AssetsParser(tmp_path / "assets")

    @pytest.fixture
    def metadata_file(self, parser: AssetsParser) -> Path:
        """Helper to create metadata.yaml file."""
        metadata_file = parser.folder / "metadata.yaml"
        metadata_file.parent.mkdir(parents=True, exist_ok=True)
        return metadata_file

    def test_parser_init(self, tmp_path):
        """Parser should store folder path correctly."""
        parser = AssetsParser(tmp_path / "assets")
        assert parser.folder == (tmp_path / "assets").expanduser().resolve()

    def test_parse_missing_folder_raises(self, parser):
        """parse() should raise FileNotFoundError if folder doesn't exist."""
        with pytest.raises(FileNotFoundError, match="Assets folder does not exist"):
            parser.parse()

    def test_parse_missing_metadata_yaml_raises(self, parser):
        """parse() should raise FileNotFoundError if metadata.yaml is missing."""
        parser.folder.mkdir(parents=True, exist_ok=True)
        with pytest.raises(FileNotFoundError, match="Missing metadata.yaml"):
            parser.parse()

    def test_parse_invalid_metadata_type_raises(self, parser, metadata_file):
        """parse() should raise ValueError if metadata type is invalid."""
        metadata_file.write_text("type: invalid\n", encoding="utf-8")

        with pytest.raises(ValueError, match="Invalid metadata.yaml"):
            parser.parse()

    def test_parse_empty_assets_folder(self, parser, metadata_file):
        """parse() should work with empty assets folder."""
        metadata_file.write_text("type: assets\n", encoding="utf-8")

        parser.parse()

        graph = parser.graph
        assert graph.assets == set()

    def test_parse_database(self, parser, metadata_file):
        """parse() should correctly parse database files."""
        metadata_file.write_text("type: assets\n", encoding="utf-8")

        databases_dir = parser.folder / "databases"
        databases_dir.mkdir()

        db_file = databases_dir / "db1.yaml"
        db_uuid = "a2dc77af-e654-49bb-b321-40f6b559a1ee"
        db_file.write_text(
            f"""
database_name: examples
uuid: {db_uuid}
""",
            encoding="utf-8",
        )

        parser.parse()

        graph = parser.graph
        assert len(graph.assets) == 1
        assets = graph.assets_of_type(AssetType.DATABASE)
        assert len(assets) == 1

    def test_parse_dataset(self, parser, metadata_file):
        """parse() should correctly parse dataset files with database dependency."""
        metadata_file.write_text("type: assets\n", encoding="utf-8")

        databases_dir = parser.folder / "databases"
        databases_dir.mkdir()

        db_file = databases_dir / "db1.yaml"
        db_uuid = "a2dc77af-e654-49bb-b321-40f6b559a1ee"
        db_file.write_text(
            f"""
database_name: examples
uuid: {db_uuid}
""",
            encoding="utf-8",
        )

        datasets_dir = parser.folder / "datasets"
        datasets_dir.mkdir()

        ds_file = datasets_dir / "ds1.yaml"
        ds_uuid = "d95a2865-53ce-1f82-a53d-8e3c89331469"
        ds_file.write_text(
            f"""
table_name: test_table
uuid: {ds_uuid}
database_uuid: {db_uuid}
""",
            encoding="utf-8",
        )

        parser.parse()

        graph = parser.graph
        assets = graph.assets
        assert len(assets) == 2

        db_asset = graph.get_asset(UUID(db_uuid))
        assert db_asset is not None

        ds_asset = graph.get_asset(UUID(ds_uuid))
        assert ds_asset is not None

        deps = graph.get_dependencies(ds_asset)
        assert db_asset in deps

    def test_parse_chart(self, parser, metadata_file):
        """parse() should correctly parse chart files with dataset dependency."""
        metadata_file.write_text("type: assets\n", encoding="utf-8")

        databases_dir = parser.folder / "databases"
        databases_dir.mkdir()

        db_file = databases_dir / "db1.yaml"
        db_uuid = "a2dc77af-e654-49bb-b321-40f6b559a1ee"
        db_file.write_text(
            f"""
database_name: examples
uuid: {db_uuid}
""",
            encoding="utf-8",
        )

        datasets_dir = parser.folder / "datasets"
        datasets_dir.mkdir()

        ds_file = datasets_dir / "ds1.yaml"
        ds_uuid = "d95a2865-53ce-1f82-a53d-8e3c89331469"
        ds_file.write_text(
            f"""
table_name: test_table
uuid: {ds_uuid}
database_uuid: {db_uuid}
""",
            encoding="utf-8",
        )

        charts_dir = parser.folder / "charts"
        charts_dir.mkdir()

        chart_file = charts_dir / "chart1.yaml"
        chart_uuid = "11111111-2222-3333-4444-555555555555"
        chart_file.write_text(
            f"""
slice_name: test_chart
uuid: {chart_uuid}
dataset_uuid: {ds_uuid}
""",
            encoding="utf-8",
        )

        parser.parse()

        graph = parser.graph
        assets = graph.assets
        assert len(assets) == 3

        chart_asset = graph.get_asset(UUID(chart_uuid))
        assert chart_asset is not None

        ds_asset = graph.get_asset(UUID(ds_uuid))
        assert ds_asset is not None

        deps = graph.get_dependencies(chart_asset)
        assert ds_asset in deps

    def test_parse_dashboard(self, parser, metadata_file):
        """parse() should correctly parse dashboard files with chart dependencies."""
        metadata_file.write_text("type: assets\n", encoding="utf-8")

        dashboards_dir = parser.folder / "dashboards"
        dashboards_dir.mkdir()

        dashboard_file = dashboards_dir / "dash1.yaml"
        dashboard_uuid = "22222222-3333-4444-5555-666666666666"
        chart_uuid = "11111111-2222-3333-4444-555555555555"
        dashboard_file.write_text(
            f"""
dashboard_title: test_dashboard
uuid: {dashboard_uuid}
position:
  CHART-1:
    type: CHART
    meta:
      chartId: {chart_uuid}
      sliceName: test_chart
""",
            encoding="utf-8",
        )

        parser.parse()

        graph = parser.graph
        assets = graph.assets
        assert len(assets) == 2

        dashboard_asset = graph.get_asset(UUID(dashboard_uuid))
        assert dashboard_asset is not None

        chart_asset = graph.get_asset(UUID(chart_uuid))
        assert chart_asset is not None

        deps = graph.get_dependencies(dashboard_asset)
        assert chart_asset in deps

    def test_parse_charts_folder_with_multiple_files(self, parser, metadata_file):
        """parse() should correctly parse multiple chart files."""
        metadata_file.write_text("type: assets\n", encoding="utf-8")

        charts_dir = parser.folder / "charts"
        charts_dir.mkdir()

        for i in range(3):
            chart_file = charts_dir / f"chart{i}.yaml"
            chart_uuid = f"00000000-0000-0000-0000-00000000000{i}"
            chart_file.write_text(
                f"""
slice_name: chart_{i}
uuid: {chart_uuid}
dataset_uuid: d95a2865-53ce-1f82-a53d-8e3c89331469
""",
                encoding="utf-8",
            )

        parser.parse()

        graph = parser.graph
        charts = graph.assets_of_type(AssetType.CHART)
        assert len(charts) == 3

    def test_parse_with_overwrite(self, parser: AssetsParser, metadata_file):
        """parse(overwrite=True) should re-parse even if already parsed."""
        metadata_file.write_text("type: assets\n", encoding="utf-8")

        parser.parse()

        databases_dir = parser.folder / "databases"
        databases_dir.mkdir()

        db_file = databases_dir / "db1.yaml"
        db_uuid = "a2dc77af-e654-49bb-b321-40f6b559a1ee"
        db_file.write_text(
            f"""
database_name: examples
uuid: {db_uuid}
""",
            encoding="utf-8",
        )

        parser.parse(overwrite=True)
        graph2 = parser.graph

        assert len(graph2.assets) == 1

    def test_parse_already_parsed_without_overwrite_raises(self, parser, metadata_file):
        """parse() should raise ValueError if already parsed without overwrite."""
        metadata_file.write_text("type: assets\n", encoding="utf-8")

        parser.parse()

        with pytest.raises(ValueError, match="Already parsed"):
            parser.parse()

    def test_asset_registry(self, parser, metadata_file):
        """asset_registry should contain parsed asset metadata."""
        metadata_file.write_text("type: assets\n", encoding="utf-8")

        databases_dir = parser.folder / "databases"
        databases_dir.mkdir()

        db_uuid = "a2dc77af-e654-49bb-b321-40f6b559a1ee"
        db_file = databases_dir / "db1.yaml"
        db_file.write_text(
            f"""
database_name: examples
uuid: {db_uuid}
""",
            encoding="utf-8",
        )

        parser.parse()

        registry = parser.asset_registry
        assert len(registry) == 1

        db_asset = Asset(uuid=UUID(db_uuid), type=AssetType.DATABASE)
        assert db_asset in registry
        assert registry[db_asset].name == "examples"

    def test_asset_registry_multiple_types(self, parser, metadata_file):
        """asset_registry should contain metadata for all parsed asset types."""
        metadata_file.write_text("type: assets\n", encoding="utf-8")

        databases_dir = parser.folder / "databases"
        databases_dir.mkdir()

        db_uuid = "a2dc77af-e654-49bb-b321-40f6b559a1ee"
        db_file = databases_dir / "db1.yaml"
        db_file.write_text(
            f"""
database_name: examples
uuid: {db_uuid}
""",
            encoding="utf-8",
        )

        datasets_dir = parser.folder / "datasets"
        datasets_dir.mkdir()

        ds_uuid = "d95a2865-53ce-1f82-a53d-8e3c89331469"
        ds_file = datasets_dir / "ds1.yaml"
        ds_file.write_text(
            f"""
table_name: test_table
uuid: {ds_uuid}
database_uuid: {db_uuid}
""",
            encoding="utf-8",
        )

        parser.parse()

        registry = parser.asset_registry
        assert len(registry) == 2
