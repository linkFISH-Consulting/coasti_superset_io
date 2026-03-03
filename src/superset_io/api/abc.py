from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import SupersetApiClient


class ClientBase:
    def __init__(self, client: SupersetApiClient) -> None:
        self.client = client

    @property
    def session(self):
        return self.client.session
