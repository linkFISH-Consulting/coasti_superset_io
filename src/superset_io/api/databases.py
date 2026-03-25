from .abc import ClientBase


class DatabasesApiClient(ClientBase):
    def get(self, database_id_or_slug: int | str) -> dict:
        """Get a single database"""
        url = "/api/v1/database"
        # Lookup by uuid not supported
        if isinstance(database_id_or_slug, str):
            url += f"?q=(filter:(col:uuid,opr:eq,value:'{database_id_or_slug}'))"
        else:
            url += f"/{database_id_or_slug}"

        res = self.session.get(url)
        res.raise_for_status()
        data = res.json()
        if isinstance(database_id_or_slug, str):
            if not data["result"]:
                raise ValueError(f"Database with uuid {database_id_or_slug} not found")
            return data["result"][0]
        return data

    def get_all(self) -> dict:
        """Get overview all databases."""
        url = "/api/v1/database/"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def remove(self, database_id_or_slug: int | str) -> None:
        """Delete a database."""
        database = self.get(database_id_or_slug)
        res = self.session.delete(f"/api/v1/database/{database['id']}")
        res.raise_for_status()
