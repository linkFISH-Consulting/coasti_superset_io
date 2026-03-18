"""Test suite for the dependency graph submodule."""

from uuid import UUID

import pytest

from superset_io.dependency_graph.assets import Asset, AssetType
from superset_io.dependency_graph.graph import DependencyGraph


class TestDependencyGraph:
    """Tests for DependencyGraph class."""

    @pytest.fixture
    def uuid1(self):
        return UUID("12345678-1234-5678-1234-567812345678")

    @pytest.fixture
    def uuid2(self):
        return UUID("87654321-4321-8765-4321-876543215678")

    @pytest.fixture
    def uuid3(self):
        return UUID("11111111-2222-3333-4444-555555555555")

    @pytest.fixture
    def asset1(self, uuid1):
        return Asset(uuid=uuid1, type=AssetType.CHART)

    @pytest.fixture
    def asset2(self, uuid2):
        return Asset(uuid=uuid2, type=AssetType.DATASET)

    @pytest.fixture
    def asset3(self, uuid3):
        return Asset(uuid=uuid3, type=AssetType.DATABASE)

    def test_empty_graph(self):
        """Empty graph should have no assets."""
        graph = DependencyGraph()
        assert graph.assets == set()
        assert graph.dependents == {}
        assert graph.dependencies == {}

    def test_add_dependency_creates_nodes(self, asset1, asset2):
        """Adding dependency should create both nodes in the graph."""
        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)
        graph.enforce_invariants()

        assert asset1 in graph.assets
        assert asset2 in graph.assets
        assert asset2 in graph.get_dependencies(asset1)
        assert asset1 in graph.get_dependent(asset2)

    def test_add_dependency_idempotent(self, asset1, asset2):
        """Adding same dependency multiple times should only create one edge."""
        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)
        graph.add_dependency(asset1, asset2)

        assert len(graph.get_dependencies(asset1)) == 1

    def test_add_asset_bulk_merge(self, asset1, asset2, asset3):
        """add_asset should bulk merge dependencies and dependents."""
        graph = DependencyGraph()
        graph.add_asset(asset1, {asset2}, {asset3})

        assert asset2 in graph.get_dependencies(asset1)
        assert asset3 in graph.get_dependent(asset1)

    def test_enforce_invariants_creates_missing_nodes(self, asset1, asset2):
        """enforce_invariants should create missing nodes in both maps."""
        graph = DependencyGraph()
        graph.add_asset(asset1, set(), set())
        graph.add_asset(asset2, set(), {asset1})
        assert len(graph.get_dependencies(asset1)) == 0
        graph.enforce_invariants()
        assert len(graph.get_dependencies(asset1)) == 1

        assert asset1 in graph.assets
        assert asset2 in graph.assets

    def test_assets_method(self, asset1, asset2, asset3):
        """assets() should return all nodes in the graph."""
        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)
        graph.add_dependency(asset2, asset3)

        all_assets = graph.assets
        assert asset1 in all_assets
        assert asset2 in all_assets
        assert asset3 in all_assets

    @pytest.mark.parametrize(
        ["types", "expected"],
        [
            ((AssetType.CHART,), {"asset1"}),
            ((AssetType.CHART, AssetType.DATABASE), {"asset1", "asset3"}),
            ((), "all"),
        ],
    )
    def test_assets_of_type(self, asset1, asset2, asset3, types, expected):
        """assets_of_type() should filter by type."""
        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)
        graph.add_dependency(asset2, asset3)

        if types == ():
            assert graph.assets_of_type() == graph.assets
        else:
            result = graph.assets_of_type(*types)
            for name in expected:
                assert locals()[name] in result

    def test_counts_by_type(self, asset1, asset2, asset3):
        """counts_by_type() should return correct counts."""
        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)
        graph.add_dependency(asset2, asset3)

        counts = graph.counts_by_type()
        assert counts[AssetType.CHART] == 1
        assert counts[AssetType.DATASET] == 1
        assert counts[AssetType.DATABASE] == 1

    @pytest.mark.parametrize("input_type", ["string", "uuid"])
    def test_get_dependencies(self, asset1, asset2, input_type):
        """get_dependencies() should work with UUID string or UUID object."""
        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)

        key = str(asset1.uuid) if input_type == "string" else asset1.uuid
        deps = graph.get_dependencies(key)
        assert asset2 in deps

    @pytest.mark.parametrize("input_type", ["string", "uuid"])
    def test_get_dependencies_unknown_asset(self, asset1, input_type):
        """get_dependencies() should return empty set for unknown asset."""
        graph = DependencyGraph()
        key = str(asset1.uuid) if input_type == "string" else asset1.uuid
        deps = graph.get_dependencies(key)
        assert deps == set()

    @pytest.mark.parametrize("input_type", ["string", "uuid"])
    def test_get_dependent(self, asset1, asset2, input_type):
        """get_dependent() should work with UUID string or UUID object."""
        graph = DependencyGraph()
        graph.add_dependency(asset1, asset2)

        key = str(asset2.uuid) if input_type == "string" else asset2.uuid
        dependents = graph.get_dependent(key)
        assert asset1 in dependents

    @pytest.mark.parametrize("input_type", ["string", "uuid"])
    def test_get_asset(self, asset1, input_type):
        """get_asset() should work with UUID string or UUID object."""
        graph = DependencyGraph()
        graph.add_asset(asset1, set(), set())

        key = str(asset1.uuid) if input_type == "string" else asset1.uuid
        found = graph.get_asset(key)
        assert found == asset1

    def test_get_asset_not_found(self, uuid1):
        """get_asset() should return None for non-existent asset."""
        graph = DependencyGraph()
        found = graph.get_asset(uuid1)
        assert found is None


class TestSubgraphExtraction:
    """Tests for subgraph extraction from DependencyGraph."""

    @pytest.fixture
    def assets(self):
        """Create sample assets for testing."""
        asset_a = Asset(uuid=UUID(int=0), type=AssetType.UNKNOWN)
        asset_b = Asset(uuid=UUID(int=1), type=AssetType.UNKNOWN)
        asset_c = Asset(uuid=UUID(int=2), type=AssetType.UNKNOWN)
        asset_d = Asset(uuid=UUID(int=3), type=AssetType.UNKNOWN)
        asset_e = Asset(uuid=UUID(int=4), type=AssetType.UNKNOWN)
        asset_f = Asset(uuid=UUID(int=5), type=AssetType.UNKNOWN)
        return asset_a, asset_b, asset_c, asset_d, asset_e, asset_f

    @pytest.fixture
    def graph(self, assets):
        """Create a sample graph for testing."""
        asset_a, asset_b, asset_c, asset_d, asset_e, asset_f = assets
        # A -> B -> C
        #       \-> D -> E
        # F
        graph = DependencyGraph()
        graph.add_dependency(asset_a, asset_b)
        graph.add_dependency(asset_b, asset_c)
        graph.add_dependency(asset_b, asset_d)
        graph.add_dependency(asset_d, asset_e)
        graph.add_asset(asset_f, set(), set())

        return graph

    def test_subgraph_upstream(self, assets, graph: DependencyGraph):
        """get_subgraph() with direction='upstream' should return correct subgraph."""
        asset_a, asset_b, asset_c, asset_d, asset_e, asset_f = assets
        subgraph = graph.get_subgraph(asset_b, direction="upstream")

        assert subgraph.get_dependencies(asset_b) == {asset_c, asset_d}
        assert subgraph.get_dependencies(asset_d) == {asset_e}

        # A & F not in graph anymore
        assert subgraph.get_asset(asset_a.uuid) is None
        assert subgraph.get_asset(asset_f.uuid) is None

    def test_subgraph_downstream(self, assets, graph: DependencyGraph):
        """get_subgraph() with direction='downstream' should return correct subgraph."""
        asset_a, asset_b, asset_c, asset_d, asset_e, asset_f = assets
        subgraph = graph.get_subgraph(asset_c, direction="downstream")

        assert subgraph.get_dependent(asset_c) == {asset_b}
        assert subgraph.get_dependent(asset_b) == {asset_a}

        assert subgraph.get_dependencies(asset_b) == {asset_c}  # D was pruned

        # C & F not in graph anymore
        assert subgraph.get_asset(asset_d.uuid) is None
        assert subgraph.get_asset(asset_e.uuid) is None
        assert subgraph.get_asset(asset_f.uuid) is None
