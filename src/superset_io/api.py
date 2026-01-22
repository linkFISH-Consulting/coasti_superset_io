import requests


class Session(requests.Session):
    base_url: str
    access_token: str
    csrf_token: str

    def __init__(
        self,
        access_token: str,
        csrf_token: str,
        base_url: str,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.base_url = base_url

        # Set initial headers
        self.headers.update(
            {
                "User-Agent": "coasti-superset-import-export/1.0.0",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
                "X-CSRFToken": csrf_token,
            }
        )

    def request(self, method: str, url: str, *args, **kwargs):
        # Prepend base_url if not already present
        if not url.startswith("http"):
            url = f"{self.base_url}{url}"
        return super().request(method, url, *args, **kwargs)


class SuperSetApiClient:
    session: Session

    def __init__(self, session: Session):
        self.session = session

    def get_dashboard(self, dashboard_id: int):
        url = f"{self.session.base_url}/dashboard/{dashboard_id}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def get_dashboards(self):
        url = f"{self.session.base_url}/api/v1/dashboard/"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
