from __future__ import annotations

import base64
import json
import logging
import re
from typing import Self, cast

import requests

log = logging.getLogger("superset_io")


class SupersetApiSession(requests.Session):
    base_url: str
    bearer_token: str | None
    csrf_token: str | None

    def __init__(
        self,
        base_url: str,
        bearer_token: str | None = None,
        csrf_token: str | None = None,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.base_url = base_url
        self.bearer_token = bearer_token
        self.csrf_token = csrf_token

        headers = {"User-Agent": "coasti-superset-import-export/1.0.0"}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        if csrf_token:
            headers["X-CSRFToken"] = csrf_token

        self.headers.update(headers)

    def request(self, method: str | bytes, url: str | bytes, *args, **kwargs):
        if isinstance(url, str) and not url.startswith("http"):
            url = f"{self.base_url}{url}"
        return super().request(method, url, *args, **kwargs)

    @classmethod
    def from_credentials(
        cls,
        base_url: str,
        username: str,
        password: str,
    ) -> Self:
        """Authenticate and return an authenticated SupersetApiSession."""
        session = cls(base_url=base_url)

        try:
            bearer_token = session._get_bearer_token(username, password)
            session.bearer_token = bearer_token
            session.headers["Authorization"] = f"Bearer {bearer_token}"
        except requests.HTTPError:
            log.debug("Failed to get bearer token")
            bearer_token = cast(str, None)
            # Some features work without authentication, in particular connection test.
            # A bit dirty, we should not pass None to `from_token`, but I do not want
            # to change the type hint of the public classmethod.

        try:
            session = cls.from_token(base_url, bearer_token, session=session)
        except RuntimeError as e:
            # this is our custom error for jwt config errors on server
            log.error(e)
            session._get_csrf_via_session_cookie(username, password)

        return session

    @classmethod
    def from_token(
        cls,
        base_url: str,
        bearer_token: str,
        session: Self | None = None,
    ) -> Self:
        """Create a SupersetApiSession from an existing access token."""

        if session is None:
            session = cls(base_url=base_url, bearer_token=bearer_token)

        # get csrf for api writes
        try:
            csrf_token = session._get_csrf_via_bearer()
            session.csrf_token = csrf_token
            session.headers["X-CSRFToken"] = csrf_token
        except requests.HTTPError:
            log.debug("Failed to get csrf token")
        return session

    def _get_bearer_token(self, username: str, password: str) -> str:
        """Get a bearer access token"""
        log.debug("Obtaining bearer access token")
        res = self.post(
            "/api/v1/security/login",
            headers={"Content-Type": "application/json"},
            json={
                "username": username,
                "password": password,
                "provider": "db",
                "refresh": False,
            },
            verify=True,
        )

        res.raise_for_status()

        token: str = res.json()["access_token"]
        log.debug(f"access token algorithm {self._jwt_header(token)}")

        return token

    def _get_csrf_via_bearer(self) -> str:
        log.debug("Obtaining csrf token via bearer")
        res = self.get("/api/v1/security/csrf_token/")

        try:
            res.raise_for_status()
        except requests.HTTPError:
            if (
                res.status_code == 422
                and "The specified alg value is not allowed" in res.text
            ):
                raise RuntimeError(
                    "Superset rejected the Bearer JWT: "
                    f"{self._jwt_header(str(self.bearer_token))}."
                    "Fix server config (e.g., JWT_ALGORITHM/allowed algorithms) "
                    "or use cookie/session auth."
                )
            raise

        return res.json()["result"]

    def _get_csrf_via_session_cookie(self, username: str, password: str) -> None:
        """
        Try to get a working csrf token via login page and session cookie.

        TODO: Verify, and this will likely be the path for keycloak.
        """

        log.debug("Obtaining csrf token via session cookie")
        res = self.get("/login/")
        res.raise_for_status()
        csrf = self._extract_csrf_from_login_html(res.text)
        if not csrf:
            raise RuntimeError(
                "Could not find csrf_token field on /login/ page. "
                "Cookie-based login fallback may not be supported/enabled."
            )

        # POST login form (Flask-AppBuilder default fields)
        res = self.post(
            "/login/",
            data={
                "username": username,
                "password": password,
                "csrf_token": csrf,
            },
            allow_redirects=True,
            headers={"Accept": "text/html,application/xhtml+xml"},
        )
        res.raise_for_status()

        res = self.get("/api/v1/security/csrf_token/")
        res.raise_for_status()
        csrf = res.json()["result"]  # TODO: Check, is this the same csrf as before?

        self.headers["X-CSRFToken"] = csrf
        self.csrf_token = csrf

    @classmethod
    def _jwt_header(cls, token: str) -> dict:
        header_b64 = token.split(".")[0]
        header_b64 += "=" * (-len(header_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(header_b64).decode("utf-8"))

    @classmethod
    def _extract_csrf_from_login_html(cls, html: str) -> str | None:
        """
        Superset's /login/ page typically includes a CSRF token in a hidden input
        called "csrf_token". This is not guaranteed across all themes/versions,
        but works in many default deployments.

        PS: not verified.
        """

        match = re.search(r'name="csrf_token"\s+type="hidden"\s+value="([^"]+)"', html)
        csrf: str | None = None
        if match:
            csrf = match.group(1)

        return csrf
