from .abc import ClientBase


class DashboardApiClient(ClientBase):
    def get(self, dashboard_id_or_slug: int | str) -> dict:
        """Get a single dashboard"""
        url = f"/api/v1/dashboard/{dashboard_id_or_slug}"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def get_all(self) -> dict:
        """Get overview all dashboards."""
        url = "/api/v1/dashboard/"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()
