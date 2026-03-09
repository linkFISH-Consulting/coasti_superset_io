from dataclasses import dataclass
from enum import Enum
from typing import TypeVar
from uuid import UUID

T = TypeVar("T")


class AssetType(Enum):
    DATABASE = 0
    DATASET = 1
    CHART = 2
    DASHBOARD = 3
    THEME = 4
    UNKNOWN = 99


@dataclass(frozen=True, slots=True)
class Asset:
    """
    Minimal asset identity used in the dependency graph.

    Only guarantees:
      - uuid (stable identity)
      - type (kind of asset)
    """

    uuid: UUID
    type: AssetType

    def __init__(self, uuid: UUID | str, type: AssetType) -> None:
        object.__setattr__(self, "uuid", UUID(uuid) if isinstance(uuid, str) else uuid)
        object.__setattr__(self, "type", type)

    def __hash__(self) -> int:
        # Stable identity hash: assets are considered the same by UUID
        return hash(self.uuid)

    def __eq__(self, other: object | UUID | str) -> bool:
        # Stable identity equality: assets are considered the same by UUID
        if isinstance(other, UUID):
            return self.uuid == other
        elif isinstance(other, Asset):
            return self.uuid == other.uuid
        elif isinstance(other, str):
            return self.uuid.__str__() == other
        return False


@dataclass(frozen=True, slots=True)
class AssetData:
    """Additional data of an asset."""

    name: str
