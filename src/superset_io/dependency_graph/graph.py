from collections import Counter
from dataclasses import dataclass, field
from uuid import UUID

from .assets import Asset, AssetType


@dataclass
class DependencyGraph:
    """Directed graph representing dependencies between assets.

    Maintains both forward (dependencies) and reverse (dependents) maps.
    """

    dependencies: dict[Asset, set[Asset]] = field(default_factory=dict)
    dependents: dict[Asset, set[Asset]] = field(default_factory=dict)

    def add_dependency(self, from_asset: Asset, to_asset: Asset) -> None:
        """Add a directed edge `from_asset -> to_asset` to the graph.

        Meaning:
            `from_asset` depends on `to_asset` (i.e., `to_asset` is an upstream
            prerequisite of `from_asset`).
        """

        self._ensure_asset(from_asset)
        self._ensure_asset(to_asset)

        self.dependencies[from_asset].add(to_asset)
        self.dependents[to_asset].add(from_asset)

    def _ensure_asset(self, asset: Asset) -> None:
        """Ensure `asset` exists as a node in the graph.

        Creates empty adjacency sets for the asset in both directions if missing:
            - dependencies[asset]: the set of assets this asset depends on
            - dependents[asset]: the set of assets that depend on this asset

        This method is idempotent (safe to call repeatedly).
        """
        self.dependencies.setdefault(asset, set())
        self.dependents.setdefault(asset, set())

    def add_asset(
        self,
        asset: Asset,
        dependencies: set[Asset],
        dependents: set[Asset],
    ):
        """Add/update an asset node and bulk-merge its relationships.

        This is a convenience method for inserting an `asset` and updating both
        adjacency maps in one call.

        Important:
            This method updates the adjacency sets *as provided*.
            It does **not** automatically enforce the forward/reverse invariant
            between `dependencies` and `dependents`.

        Make sure to call enforce_invariants after you are done!
        Returns:
            None
        """
        self._ensure_asset(asset)
        self.dependencies[asset].update(dependencies)
        self.dependents[asset].update(dependents)

    def enforce_invariants(self) -> None:
        """Align `dependencies` and `dependents` by inserting missing mirrors.

        After this runs, the graph satisfies (by *unioning* information from both sides)

            to_asset in self.dependencies[from_asset]
            iff
            from_asset in self.dependents[to_asset]

        Behavior:
            - Adds missing nodes to both maps.
            - Adds missing mirrored edges in whichever direction they are absent.
            - Does NOT remove edges that exist on one side; instead it mirrors them
              to the other side (i.e., it takes the union of both representations).

        This is useful if you did fast ingestion that may have left the two maps
        out of sync, and you just want them aligned.
        """
        deps = self.dependencies
        dents = self.dependents

        # Ensure all known nodes exist in both maps
        all_assets: set[Asset] = set(deps) | set(dents)
        for frm, tos in deps.items():
            all_assets.update(tos)
        for to, frms in dents.items():
            all_assets.update(frms)

        for asset in all_assets:
            self._ensure_asset(asset)

        for frm, tos in deps.items():
            for to in tos:
                dents[to].add(frm)

        for to, frms in dents.items():
            for frm in frms:
                deps[frm].add(to)

    # ---------------------------------- Uility ---------------------------------- #
    # Maybe move to another module if it gets out of hand here

    @property
    def assets(self) -> set[Asset]:
        all_assets: set[Asset] = set(self.dependencies) | set(self.dependents)
        for tos in self.dependencies.values():
            all_assets.update(tos)
        for frms in self.dependents.values():
            all_assets.update(frms)
        return all_assets

    def assets_of_type(self, *types: AssetType) -> set[Asset]:
        """Return all assets whose type is in `types`."""
        if not types:
            return self.assets
        wanted = set(types)
        return {a for a in self.assets if a.type in wanted}

    def counts_by_type(self) -> Counter[AssetType]:
        """Return counts of assets by AssetType."""
        return Counter(a.type for a in self.assets)

    def _asset_key(self, asset: str | UUID | Asset) -> Asset:
        """Normalize lookup key to an Asset so dict indexing works."""
        if isinstance(asset, Asset):
            return asset
        # Type is irrelevant if Asset equality/hash is UUID-based
        return Asset(uuid=asset, type=AssetType.UNKNOWN)

    def get_dependencies(self, asset: str | UUID | Asset) -> set[Asset]:
        """Return upstream dependencies for `asset` (empty set if unknown)."""
        return self.dependencies.get(self._asset_key(asset), set())

    def get_dependent(self, asset: str | UUID | Asset) -> set[Asset]:
        """Return downstream dependents for `asset`  (empty set if unknown)."""
        return self.dependents.get(self._asset_key(asset), set())

    def get_asset(self, asset: str | UUID) -> Asset | None:
        """Helper to get a asset via UUID/str.

        None if not in graph
        """
        for a in self.assets:
            if a == asset:
                return a
        return None
