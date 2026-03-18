from .abc import ClientBase


class ChartsApiClient(ClientBase):
    def get(self, chart_id_or_slug: int | str) -> dict:
        """Get a single chart"""
        url = f"/api/v1/chart/{chart_id_or_slug}"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def get_all(self) -> dict:
        """Get overview all charts."""
        url = "/api/v1/chart/"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def remove(self, chart_id_or_slug: int | str) -> None:
        """Delete a chart."""
        chart = self.get(chart_id_or_slug)
        res = self.session.delete(f"/api/v1/chart/{chart['result']['id']}")
        res.raise_for_status()
