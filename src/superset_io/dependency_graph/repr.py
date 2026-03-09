"""
Rich rendering helpers for dependency graphs (print a dependency tree with colors).

Adjust the import of Asset/AssetType/DependencyGraph to match your project layout.
"""

from __future__ import annotations

import colorsys
from collections.abc import Callable
from typing import Literal

from rich.console import Console
from rich.text import Text
from rich.theme import Theme
from rich.tree import Tree

from .assets import Asset, AssetData, AssetType
from .graph import DependencyGraph

__all__ = [
    "ASSET_THEME",
    "BASE_HEX",
    "make_console",
    "color_for_asset",
    "rich_label",
    "print_dep_tree_rich",
]


ASSET_THEME = Theme(
    {
        "asset.sep": "dim",
        "asset.uuid": "white",
        "asset.ref": "dim italic",
        "asset.name": "bold white",
        "tree.guide": "grey50",
    }
)

# Base colors per type
BASE_HEX: dict[AssetType, str] = {
    AssetType.DATABASE: "#00B8D9",  # cyan-ish
    AssetType.DATASET: "#36B37E",  # green-ish
    AssetType.CHART: "#FFAB00",  # yellow/orange-ish
    AssetType.DASHBOARD: "#6554C0",  # purple-ish
    AssetType.UNKNOWN: "#7A869A",  # grey-ish
}


def make_console(*, theme: Theme = ASSET_THEME) -> Console:
    """Create a Rich console configured with the asset theme."""
    return Console(theme=theme)


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def _hex_to_rgb01(h: str) -> tuple[float, float, float]:
    h = h.lstrip("#")
    r = int(h[0:2], 16) / 255.0
    g = int(h[2:4], 16) / 255.0
    b = int(h[4:6], 16) / 255.0
    return r, g, b


def _rgb01_to_hex(rgb: tuple[float, float, float]) -> str:
    r, g, b = (int(_clamp(c) * 255) for c in rgb)
    return f"#{r:02x}{g:02x}{b:02x}"


def color_for_asset(a: Asset, *, base_hex: dict[AssetType, str] = BASE_HEX) -> str:
    """
    Returns a hex color that is a deterministic "offset" from the base color
    for the asset type. Same UUID => same color every time.
    """
    base = base_hex.get(a.type, base_hex[AssetType.UNKNOWN])
    r, g, b = _hex_to_rgb01(base)
    h, l, s = colorsys.rgb_to_hls(r, g, b)  # noqa: E741

    # Deterministic jitter from UUID (stable across runs)
    x: int = a.uuid.int  # type: ignore

    # small hue shift in [-0.06, +0.06]
    hue_jitter = (((x >> 8) % 10) - 5) / 5.0 * 0.06
    # small lightness shift in [-0.12, +0.12]
    light_jitter = (((x >> 20) % 10) - 5) / 5.0 * 0.12
    # small saturation shift in [-0.10, +0.10]
    sat_jitter = (((x >> 32) % 10) - 5) / 5.0 * 0.10

    h = (h + hue_jitter) % 1.0
    l = _clamp(l + light_jitter, 0.20, 0.85)  # noqa: E741
    s = _clamp(s + sat_jitter, 0.25, 1.00)

    rr, gg, bb = colorsys.hls_to_rgb(h, l, s)
    return _rgb01_to_hex((rr, gg, bb))


def rich_label(
    a: Asset, registry: dict[Asset, AssetData] | None = None, uuids: bool = False
) -> Text:
    """Create a Rich Text label for an asset, with color and optional UUID."""
    c = color_for_asset(a)
    text_parts = [
        (a.type.name, f"bold {c}"),
        (":", "asset.sep"),
    ]
    if registry and a in registry:
        text_parts.append((registry[a].name, "asset.name"))
        if uuids:
            text_parts.append((f" ({a.uuid})", "asset.uuid"))
    else:
        text_parts.append((str(a.uuid), "asset.uuid"))
    return Text.assemble(
        *text_parts,
    )


def print_dep_tree_rich(
    g: DependencyGraph,
    root: Asset,
    *,
    direction: Literal["upstream", "downstream"] = "upstream",
    max_depth: int | None = None,
    label: Callable[[Asset], Text] = rich_label,
    console: Console | None = None,
) -> None:
    """
    Print a dependency tree for `root`.

    Parameters
    ----------
    direction:
        "upstream" => walk g.dependencies
        "downstream" => walk g.dependents
    console:
        Optional Rich Console; if omitted, one is created with ASSET_THEME.
    """
    if direction not in {"upstream", "downstream"}:
        raise ValueError('direction must be "upstream" or "downstream"')

    adj = g.dependencies if direction == "upstream" else g.dependents
    seen: set[Asset] = set()

    root_tree = Tree(label(root), guide_style="tree.guide")

    def rec(node: Asset, tree: Tree, depth: int) -> None:
        if max_depth is not None and depth >= max_depth:
            return

        children = sorted(
            adj.get(node, set()), key=lambda a: (a.type.value, str(a.uuid))
        )
        for child in children:
            if child in seen:
                tree.add(Text.assemble(label(child), (" (ref)", "asset.ref")))
                continue

            branch = tree.add(label(child))
            seen.add(child)
            rec(child, branch, depth + 1)

    seen.add(root)
    rec(root, root_tree, depth=0)

    (console or make_console()).print(root_tree)
