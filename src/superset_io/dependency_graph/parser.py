import logging
import os
from concurrent.futures import (
    ProcessPoolExecutor,
    ThreadPoolExecutor,
    as_completed,
)
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml

from .assets import Asset, AssetType
from .graph import DependencyGraph

log = logging.getLogger("superset_io")


class ParserError(Exception):
    def __init__(
        self, message: str, path: Path | None = None, *, cause: Exception | None = None
    ) -> None:
        self.message = message
        self.path = path
        self.cause = cause
        parts = [message]
        if path is not None:
            parts.append(f"path={path}")
        super().__init__(" | ".join(parts))


class AssetsParser:
    """Parses an Superset Assets folder"""

    executor: type[ProcessPoolExecutor | ThreadPoolExecutor] | None

    def __init__(self) -> None:
        self.executor = ProcessPoolExecutor

    def __call__(self, folder: Path) -> DependencyGraph:
        """Parse an assets folder into one dependency graphs."""

        folder = folder.expanduser().resolve()

        if not folder.exists():
            raise FileNotFoundError(f"Assets folder does not exist: {folder}")
        if not folder.is_dir():
            raise NotADirectoryError(f"Assets folder is not a directory: {folder}")

        # Check has metadata.yaml and type=assets
        metadata_file = folder / "metadata.yaml"
        if not metadata_file.exists():
            raise FileNotFoundError(
                f"Missing metadata.yaml in assets folder: {metadata_file}"
            )

        # Validate metadata.yaml
        metadata = self.__load_yaml(metadata_file)
        if metadata.get("type") != "assets":
            raise ValueError(
                f"Invalid metadata.yaml (expected type: assets): {metadata_file}"
            )

        # Parse
        return self._parse(folder)

    @staticmethod
    def __load_yaml(file: Path) -> dict[str, Any]:
        try:
            with file.open(encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ParserError("Invalid YAML", file, cause=e) from e

        if data is None:
            return {}
        if not isinstance(data, dict):
            raise ParserError("YAML root must be a mapping/object", file)
        return data

    @staticmethod
    def __parse_uuid(data: Any) -> UUID | None:
        if isinstance(data, str):
            return UUID(data)
        return None

    def _parse(self, folder: Path) -> DependencyGraph:
        if not self.executor:
            return self._parse_no_thread(folder)

        mapping = {
            "charts/**/*.yaml": self._parse_charts,
            "dashboards/**/*.yaml": self._parse_dashboard,
            "databases/**/*.yaml": self._parse_database,
            "datasets/**/*.yaml": self._parse_dataset,
        }

        graph = DependencyGraph()
        # FIXME: with python 3.14 it should be possible to
        # to switch to ThreadPool for same speedup
        with self.executor(max_workers=os.cpu_count()) as executor:
            futures = [
                executor.submit(func, path)
                for pattern, func in mapping.items()
                for path in folder.glob(pattern)
            ]

            for fut in as_completed(futures):
                result = fut.result()
                if result is None:
                    continue
                asset, deps, dents = result
                graph.add_asset(asset, deps, dents)

        graph.enforce_invariants()
        return graph

    def _parse_no_thread(self, folder: Path) -> DependencyGraph:
        mapping = {
            "charts/**/*.yaml": self._parse_charts,
            "dashboards/**/*.yaml": self._parse_dashboard,
            "databases/**/*.yaml": self._parse_database,
            "datasets/**/*.yaml": self._parse_dataset,
        }

        graph = DependencyGraph()

        for pattern, func in mapping.items():
            for path in folder.glob(pattern):
                result = func(path)
                if result is None:
                    continue
                asset, deps, dents = result
                graph.add_asset(asset, deps, dents)

        graph.enforce_invariants()
        return graph

    def _parse_charts(self, path: Path) -> tuple[Asset, set[Asset], set[Asset]] | None:
        """Parse a chart file

        Yields [chart, dependencies, dependents]
        """

        chart = self.__load_yaml(path)
        if not (uuid := chart.get("uuid")):
            log.warning(f"Chart: f{path} has no uuid. Skipping!")
            return None

        chart_asset = Asset(uuid=uuid, type=AssetType.CHART)

        # Charts has dataset as dependency
        dependencies = set()
        if dataset_uuid := self.__parse_uuid(chart.get("dataset_uuid")):
            dependencies.add(Asset(uuid=dataset_uuid, type=AssetType.DATASET))

        return chart_asset, dependencies, set()

    def _parse_dashboard(
        self, path: Path
    ) -> tuple[Asset, set[Asset], set[Asset]] | None:
        dashboard = self.__load_yaml(path)

        if not (uuid := dashboard.get("uuid")):
            log.warning(f"Dashboard: f{path} has no uuid. Skipping!")
            return None

        dashboard_asset = Asset(uuid=uuid, type=AssetType.DASHBOARD)

        dependencies = set()
        if theme_uuid := self.__parse_uuid(dashboard.get("theme_uuid")):
            dependencies.add(Asset(uuid=theme_uuid, type=AssetType.THEME))

        dependents = set()
        for position in dashboard.get("position", {}).values():
            if not isinstance(position, dict):
                continue
            if position.get("type") == "CHART" and (
                chart_uuid := position.get("meta", {}).get("uuid")
            ):
                dependents.add(Asset(chart_uuid, type=AssetType.CHART))

        return dashboard_asset, dependencies, dependents

    def _parse_database(
        self, path: Path
    ) -> tuple[Asset, set[Asset], set[Asset]] | None:
        database = self.__load_yaml(path)

        if not (uuid := database.get("uuid")):
            log.warning(f"Database: f{path} has no uuid. Skipping!")
            return None

        return Asset(uuid=uuid, type=AssetType.DATABASE), set(), set()

    def _parse_dataset(self, path: Path) -> tuple[Asset, set[Asset], set[Asset]] | None:
        dataset = self.__load_yaml(path)

        if not (uuid := dataset.get("uuid")):
            log.warning(f"Database: f{path} has no uuid. Skipping!")
            return None

        dataset_asset = Asset(uuid=uuid, type=AssetType.DATASET)
        # Charts has dataset as dependency
        dependencies = set()
        if database_uuid := self.__parse_uuid(dataset.get("database_uuid")):
            dependencies.add(Asset(uuid=database_uuid, type=AssetType.DATABASE))

        return dataset_asset, dependencies, set()
