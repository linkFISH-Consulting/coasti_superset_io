from collections import defaultdict
from pathlib import Path
from typing import Annotated, Literal

import typer
from prompt_toolkit.shortcuts import choice

from superset_io.dependency_graph import Asset, AssetsParser, AssetType, DependencyGraph
from superset_io.dependency_graph.repr import print_dep_tree_rich

explore_app = typer.Typer(
    no_args_is_help=True,
    help="Explore downloaded superset assets.",
)


class Context(typer.Context):
    obj: DependencyGraph


@explore_app.callback()
def load_assets(
    ctx: Context,
    dst_path: Annotated[
        Path,
        typer.Argument(
            file_okay=True,
            dir_okay=True,
            help="Destination zip or directory.",
        ),
    ],
):
    ctx.obj = AssetsParser()(dst_path)


@explore_app.command(name="list")
def list_(ctx: Context):
    """List assets from a downloaded assets folder or zip."""
    grouped: dict[AssetType, set[Asset]] = defaultdict(set)
    for asset in ctx.obj.assets:
        grouped[asset.type].add(asset)

    for asset_type, assets in grouped.items():
        print(f"{asset_type.name}:")
        for asset in assets:
            print(f"\t{asset.uuid}")


@explore_app.command()
def graph(
    ctx: Context,
    asset: Annotated[
        str | None,
        typer.Option(help="UUID of asset. If not given, will be prompted."),
    ] = None,
    direction: Annotated[
        Literal["upstream", "downstream"] | None, typer.Option(help="")
    ] = None,
):
    """Dependency graph of a specific asset."""
    asset_ = prompt_for_asset(ctx.obj, asset)

    if direction is None:
        direction = choice(
            message="Explore direction:",
            options=[
                ("upstream", "Dependencies (what this asset relies on)"),
                ("downstream", "Dependents (what relies on this asset)"),
            ],
            default="upstream",
        )

    print_dep_tree_rich(
        ctx.obj,
        root=asset_,
        direction=direction,  # type: ignore[arg-type]
    )


def prompt_for_asset(
    g: DependencyGraph,
    asset: str | None = None,
) -> Asset:
    # Prompt for assets
    if asset is None:
        print(" Select asset:")
        asset_type = choice(
            message=" Asset type:",
            options=[(a, a.name) for a in AssetType],
            default=AssetType.DATABASE,
        )

        assets = [*g.assets_of_type(asset_type)]
        if len(assets) == 0:
            raise Exception(f"No assets of type {asset_type} found.")

        return choice(
            message=f" {asset_type.name.lower().capitalize()}s:",
            options=[(a, str(a.uuid)) for a in assets],
            default=assets[0],
        )
    else:
        asset_ = g.get_asset(asset)
        if not asset_:
            raise Exception(f"Asset {asset} not found!")
        return asset_
