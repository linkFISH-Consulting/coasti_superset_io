import logging

import requests

from .assets import AssetsApiClient
from .dashboards import DashboardApiClient
from .session import SupersetApiSession

log = logging.getLogger("superset_io")


class SupersetApiClient:
    session: SupersetApiSession
    assets: AssetsApiClient
    dashboards: DashboardApiClient

    def __init__(self, session: SupersetApiSession):
        self.session = session
        self.assets = AssetsApiClient(self)
        self.dashboards = DashboardApiClient(self)

    def test_connection(self) -> bool:
        """Test connection is possible.

        Smoke test that:
        0) We can connect via /health
        1) Bearer auth is accepted (GET /api/v1/log/)
        2) CSRF token header is accepted (POST /api/v1/assets/import/)

        Returns true if accessible returns false if not
        """

        # 0) Server reachable
        res = self.session.get("/health")
        try:
            res.raise_for_status()
            log.info("✅ Server is reachable.")
        except requests.HTTPError as e:
            log.error(f"❌ Server not reachable: {e}")
            log.debug(f"  {e.response.text}" if e.response else "")
            return False

        # 1) Access token works
        res = self.session.get("/api/v1/log/")
        try:
            res.raise_for_status()
            log.info("✅ Access token working, can download assets.")
        except requests.HTTPError as e:
            msg = "❌ Could not access API that requires bearer token"
            if res.status_code == 401:
                msg += (
                    ". Check credentials and JWT_ALGORITHM in your superset_config.py"
                )
            log.error(f"{msg}\n  {e}")
            return False

        # 2) CSRF works: pick a POST endpoint that requires CSRF,
        # Send invalid payload so we don't create anything.
        # Expectation:
        #   - If CSRF is missing/invalid => typically 400/403 (CSRF-related)
        #   - If CSRF is accepted       => typically 400/422 (payload validation) or 403
        if not self.session.headers.get("X-CSRFToken"):
            log.error(
                "❌ No X-CSRFToken set on session; cannot validate CSRF handling."
            )
            return False

        res = self.session.post(
            "/api/v1/assets/import/",
            json={},  # invalid; we only want to get past CSRF
            headers={"Referer": self.session.base_url.rstrip("/") + "/"},
        )

        try:
            # Anything else is unexpected
            res.raise_for_status()
            log.info("✅ CSRF token working, can upload assets.")
        except requests.HTTPError as e:
            try:
                error = res.json()["errors"][0]["error_type"]
                if error == "INVALID_PAYLOAD_FORMAT_ERROR":
                    log.info("✅ CSRF token working, can upload assets.")
                else:
                    raise ValueError("Expected INVALID_PAYLOAD_FORMAT_ERROR error!")
            except Exception:
                log.error(f"❌ CSRF validation failed: {e} {res.text}")
                return False

        return True


__all__ = ["SupersetApiClient"]
