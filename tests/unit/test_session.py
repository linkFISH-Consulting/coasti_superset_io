import base64
from unittest.mock import Mock

import pytest
import requests

from superset_io.api.session import SupersetApiSession


@pytest.fixture
def fake_jwt():
    header = (
        base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}')
        .decode("ascii")
        .rstrip("=")
    )
    return f"{header}.payload.sig"


class TestSupersetApiSession:
    """Unit tests for SupersetApiSession."""

    def test_init_sets_headers_conditionally(self):
        s1 = SupersetApiSession(base_url="http://localhost:8088")
        assert s1.base_url == "http://localhost:8088"
        assert "User-Agent" in s1.headers
        assert "Authorization" not in s1.headers
        assert "X-CSRFToken" not in s1.headers

        s2 = SupersetApiSession(
            base_url="http://localhost:8088",
            bearer_token="tok",
            csrf_token="csrf",
        )
        assert s2.headers["Authorization"] == "Bearer tok"
        assert s2.headers["X-CSRFToken"] == "csrf"

    @pytest.mark.parametrize(
        ("given", "expected"),
        [
            ("/api/v1/dashboard/", "http://localhost:8088/api/v1/dashboard/"),
            ("https://example.com/api/test", "https://example.com/api/test"),
        ],
    )
    def test_session_request_normalizes_urls(self, monkeypatch, given, expected):
        session = SupersetApiSession(base_url="http://localhost:8088")

        request_mock = Mock(return_value=Mock(status_code=200))
        monkeypatch.setattr(requests.Session, "request", request_mock)

        session.request("GET", given)

        assert request_mock.call_args[0][0] == "GET"
        assert request_mock.call_args[0][1] == expected

    def test_from_token_http_error_does_not_crash_or_set_csrf(self, monkeypatch):
        monkeypatch.setattr(
            SupersetApiSession,
            "_get_csrf_via_bearer",
            Mock(side_effect=requests.HTTPError("no csrf")),
        )

        session = SupersetApiSession.from_token(
            base_url="http://localhost:8088",
            bearer_token="bearer-123",
        )

        assert session.bearer_token == "bearer-123"
        assert session.headers["Authorization"] == "Bearer bearer-123"
        assert session.csrf_token is None
        assert "X-CSRFToken" not in session.headers

    def test_from_token_success(self, monkeypatch):
        monkeypatch.setattr(
            SupersetApiSession,
            "_get_csrf_via_bearer",
            Mock(return_value="csrf-from-bearer"),
        )

        session = SupersetApiSession.from_token(
            base_url="http://localhost:8088",
            bearer_token="bearer-456",
        )

        assert session.bearer_token == "bearer-456"
        assert session.headers["Authorization"] == "Bearer bearer-456"
        assert session.csrf_token == "csrf-from-bearer"
        assert session.headers["X-CSRFToken"] == "csrf-from-bearer"

    def test_from_token_with_existing_session(self, monkeypatch):
        existing_session = SupersetApiSession(base_url="http://localhost:8088")

        monkeypatch.setattr(
            SupersetApiSession,
            "_get_csrf_via_bearer",
            Mock(return_value="csrf-789"),
        )

        result = SupersetApiSession.from_token(
            base_url="http://localhost:8088",
            bearer_token="bearer-789",
            session=existing_session,
        )

        assert result is existing_session
        assert result.csrf_token == "csrf-789"
        assert result.headers["X-CSRFToken"] == "csrf-789"

    def test_get_csrf_via_session_cookie_no_csrf_field(self, monkeypatch):
        session = SupersetApiSession(base_url="http://localhost:8088")

        login_res = Mock()
        login_res.text = "<html><body>No CSRF here</body></html>"
        login_res.raise_for_status = Mock()

        monkeypatch.setattr(session, "get", Mock(return_value=login_res))

        with pytest.raises(RuntimeError, match="Could not find csrf_token field"):
            session._get_csrf_via_session_cookie("admin", "password")


class TestFromCredentials:
    def test_from_credentials(self, monkeypatch):
        monkeypatch.setattr(
            SupersetApiSession,
            "_get_bearer_token",
            Mock(return_value="bearer-123"),
        )
        monkeypatch.setattr(
            SupersetApiSession,
            "_get_csrf_via_bearer",
            Mock(return_value="csrf-abc"),
        )

        session = SupersetApiSession.from_credentials(
            base_url="http://localhost:8088",
            username="admin",
            password="admin",
        )

        assert session.bearer_token == "bearer-123"
        assert session.headers["Authorization"] == "Bearer bearer-123"
        assert session.csrf_token == "csrf-abc"
        assert session.headers["X-CSRFToken"] == "csrf-abc"

    def test_from_credentials_fallback(self, monkeypatch):
        monkeypatch.setattr(
            SupersetApiSession,
            "_get_bearer_token",
            Mock(return_value="bearer-123"),
        )

        # Force the `from_token()` path to raise your custom RuntimeError
        monkeypatch.setattr(
            SupersetApiSession,
            "_get_csrf_via_bearer",
            Mock(side_effect=RuntimeError("Superset rejected the Bearer JWT")),
        )

        cookie_fallback = Mock()
        monkeypatch.setattr(
            SupersetApiSession,
            "_get_csrf_via_session_cookie",
            cookie_fallback,
        )

        SupersetApiSession.from_credentials(
            base_url="http://localhost:8088",
            username="admin",
            password="admin",
        )

        cookie_fallback.assert_called_once()

    def test_from_credentials_http_error(self, monkeypatch):
        # Force bearer retrieval to fail
        monkeypatch.setattr(
            SupersetApiSession,
            "_get_bearer_token",
            Mock(side_effect=requests.HTTPError("login failed")),
        )

        # Patch from_token so we don't depend on CSRF internals here.
        # Return the provided session unchanged.
        from_token_mock = Mock(
            side_effect=lambda base_url, bearer_token, session=None: session
        )
        monkeypatch.setattr(SupersetApiSession, "from_token", from_token_mock)

        session = SupersetApiSession.from_credentials(
            base_url="http://localhost:8088",
            username="admin",
            password="admin",
        )

        # No bearer token set, so no Authorization header should be present
        assert session.bearer_token is None
        assert "Authorization" not in session.headers

        # from_token should still be called (current behavior), passing None as
        # bearer token
        from_token_mock.assert_called_once()
        args, kwargs = from_token_mock.call_args
        assert args[0] == "http://localhost:8088"
        assert args[1] is None
        assert kwargs["session"] is session


class TestBearerToken:
    def test_get_bearer_token_success(self, monkeypatch, fake_jwt):
        session = SupersetApiSession(base_url="http://localhost:8088")

        res = Mock()
        res.json = Mock(return_value={"access_token": fake_jwt})
        res.raise_for_status = Mock()

        monkeypatch.setattr(session, "post", Mock(return_value=res))

        token = session._get_bearer_token("admin", "password")

        assert token == fake_jwt

    def test_get_bearer_token_http_error(self, monkeypatch):
        session = SupersetApiSession(base_url="http://localhost:8088")

        res = Mock()
        res.raise_for_status = Mock(side_effect=requests.HTTPError("Network error"))

        monkeypatch.setattr(session, "post", Mock(return_value=res))

        with pytest.raises(requests.HTTPError):
            session._get_bearer_token("admin", "password")

    def test_get_csrf_via_bearer(self, monkeypatch, fake_jwt):
        session = SupersetApiSession(
            base_url="http://localhost:8088",
            bearer_token=fake_jwt,
        )

        res = Mock()
        res.ok = True
        res.json = Mock(return_value={"result": "csrf-abc"})

        monkeypatch.setattr(session, "get", Mock(return_value=res))

        assert session._get_csrf_via_bearer() == "csrf-abc"

    def test_get_csrf_via_bearer_http_error(self, monkeypatch, fake_jwt):
        session = SupersetApiSession(
            base_url="http://localhost:8088",
            bearer_token=fake_jwt,
        )

        res = Mock()
        res.ok = False
        res.status_code = 422
        res.text = "The specified alg value is not allowed"
        res.raise_for_status = Mock(side_effect=requests.HTTPError("login failed"))

        monkeypatch.setattr(session, "get", Mock(return_value=res))

        with pytest.raises(RuntimeError, match="Superset rejected the Bearer JWT"):
            session._get_csrf_via_bearer()


class TestSessionCookie:
    def test_get_csrf_via_session_cookie_success(self, monkeypatch):
        session = SupersetApiSession(base_url="http://localhost:8088")

        # 1) GET /login/ returns HTML page
        login_get_res = Mock()
        login_get_res.text = '<input name="csrf_token" type="hidden" value="csrf-abc">'
        login_get_res.raise_for_status = Mock()

        # 2) POST /login/ succeeds (sets cookies in real life; here just no error)
        login_post_res = Mock()
        login_post_res.raise_for_status = Mock()

        # 3) GET csrf endpoint returns JSON csrf
        csrf_get_res = Mock()
        csrf_get_res.raise_for_status = Mock()
        csrf_get_res.json = Mock(return_value={"result": "csrf-abc"})

        # Wire the call sequence
        get_mock = Mock(side_effect=[login_get_res, csrf_get_res])
        post_mock = Mock(return_value=login_post_res)
        monkeypatch.setattr(session, "get", get_mock)
        monkeypatch.setattr(session, "post", post_mock)

        # Act
        session._get_csrf_via_session_cookie("admin", "password")

        # Assert: calls
        get_mock.assert_any_call("/login/")
        post_mock.assert_called_once_with(
            "/login/",
            data={
                "username": "admin",
                "password": "password",
                "csrf_token": "csrf-abc",
            },
            allow_redirects=True,
            headers={"Accept": "text/html,application/xhtml+xml"},
        )
        get_mock.assert_any_call("/api/v1/security/csrf_token/")

        # Assert: session mutated
        assert session.csrf_token == "csrf-abc"
        assert session.headers["X-CSRFToken"] == "csrf-abc"
