from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar

import typer
from rich.console import Console
from rich.text import Text

from superset_io.api import SupersetApiClient


class Context(typer.Context):
    """Typed typer context for global state management"""

    obj: SupersetApiClient


E = TypeVar("E", bound=Exception, covariant=True)


def default_convert(e: Exception):
    return f"{e.__class__.__name__}: {str(e)}"


P = ParamSpec("P")
R = TypeVar("R")


def catch_exception(
    exception: type[E],
    exit_code: int = 1,
    converter: Callable[[E], str | Text] = default_convert,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Simple decorator that catches exceptions and prints them
    using typer.echo.

    This omits the long stacktrace.
    """
    err_console = Console(stderr=True)

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exception as e:
                err_console.print(converter(e))
                raise typer.Exit(code=exit_code)

        return wrapper

    return decorator
