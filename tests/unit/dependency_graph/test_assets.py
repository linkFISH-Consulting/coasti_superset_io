from uuid import UUID

import pytest

from superset_io.dependency_graph.assets import Asset, AssetType


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
