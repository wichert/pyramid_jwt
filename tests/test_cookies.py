import uuid

import pytest

from pyramid.interfaces import IAuthenticationPolicy
from webob import Request
from zope.interface.verify import verifyObject

from pyramid_jwt.policy import JWTCookieAuthenticationPolicy


@pytest.fixture(scope="module")
def principal():
    return str(uuid.uuid4())


@pytest.fixture(scope="module")
def dummy_request():
    return Request.blank("/")


def test_interface():
    verifyObject(IAuthenticationPolicy, JWTCookieAuthenticationPolicy("secret"))


def test_cookie(dummy_request, principal):
    policy = JWTCookieAuthenticationPolicy("secret")
    cookie = policy.remember(dummy_request, principal).pop()

    assert len(cookie) == 2

    header, cookie = cookie
    assert header == "Set-Cookie"
    assert len(cookie) > 0


def test_cookie_name(dummy_request, principal):
    policy = JWTCookieAuthenticationPolicy("secret", cookie_name="auth")
    _, cookie = policy.remember(dummy_request, principal).pop()

    name, value = cookie.split("=", 1)
    assert name == "auth"


def test_secure_cookie():
    policy = JWTCookieAuthenticationPolicy("secret", https_only=True)
    dummy_request = Request.blank("/")
    _, cookie = policy.remember(dummy_request, str(uuid.uuid4())).pop()

    assert "; secure;" in cookie
    assert "; HttpOnly" in cookie


def test_insecure_cookie(dummy_request, principal):
    policy = JWTCookieAuthenticationPolicy("secret", https_only=False)
    _, cookie = policy.remember(dummy_request, principal).pop()

    assert "; secure;" not in cookie
    assert "; HttpOnly" in cookie


def test_cookie_decode(dummy_request, principal):
    policy = JWTCookieAuthenticationPolicy("secret", https_only=False)

    header, cookie = policy.remember(dummy_request, principal).pop()
    name, value = cookie.split("=", 1)

    value, _ = value.split(";", 1)
    dummy_request.cookies = {name: value}

    claims = policy.get_claims(dummy_request)
    assert claims["sub"] == principal


def test_invalid_cookie_reissue(dummy_request, principal):
    policy = JWTCookieAuthenticationPolicy("secret", https_only=False, reissue_time=10)

    token = "invalid value"
    header, cookie = policy.remember(dummy_request, token).pop()
    name, value = cookie.split("=", 1)

    value, _ = value.split(";", 1)
    dummy_request.cookies = {name: value}

    claims = policy.get_claims(dummy_request)
    assert not claims


def test_cookie_max_age(dummy_request, principal):
    policy = JWTCookieAuthenticationPolicy("secret", cookie_name="auth", expiration=100)
    _, cookie = policy.remember(dummy_request, principal).pop()
    _, value = cookie.split("=", 1)

    _, meta = value.split(";", 1)
    assert "Max-Age=100" in meta
    assert "expires" in meta


@pytest.mark.freeze_time
def test_expired_token(dummy_request, principal, freezer):
    policy = JWTCookieAuthenticationPolicy("secret", cookie_name="auth", expiration=1)
    _, cookie = policy.remember(dummy_request, principal).pop()
    name, value = cookie.split("=", 1)

    freezer.tick(delta=2)

    value, _ = value.split(";", 1)
    dummy_request.cookies = {name: value}
    claims = policy.get_claims(dummy_request)

    assert claims == {}
