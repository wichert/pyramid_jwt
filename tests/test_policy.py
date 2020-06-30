# vim: fileencoding=utf-8
import warnings
from datetime import timedelta

from webob import Request
from zope.interface.verify import verifyObject
from pyramid.security import forget
from pyramid.security import remember
from pyramid.testing import testConfig
from pyramid.testing import DummyRequest
from pyramid.testing import DummySecurityPolicy
from pyramid.interfaces import IAuthenticationPolicy
from pyramid_jwt.policy import (
    JWTAuthenticationPolicy,
    PyramidJSONEncoderFactory,
    JWTCookieAuthenticationPolicy,
)
import uuid
import pytest
from json.encoder import JSONEncoder
from uuid import UUID


def test_interface():
    verifyObject(IAuthenticationPolicy, JWTAuthenticationPolicy("secret"))


def test_token_most_be_str():
    policy = JWTAuthenticationPolicy("secret")
    token = policy.create_token(15)
    assert isinstance(token, str)


def test_minimal_roundtrip():
    policy = JWTAuthenticationPolicy("secret")
    request = Request.blank("/")
    request.authorization = ("JWT", policy.create_token(15))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == 15


def test_audience_valid():
    policy = JWTAuthenticationPolicy("secret", audience="example.org")
    token = policy.create_token(15, name="Jöhn", admin=True, audience="example.org")
    request = Request.blank("/")
    request.authorization = ("JWT", token)
    jwt_claims = policy.get_claims(request)
    assert jwt_claims["aud"] == "example.org"


def test_audience_invalid():
    policy = JWTAuthenticationPolicy("secret", audience="example.org")
    token = policy.create_token(15, name="Jöhn", admin=True, audience="example.com")
    request = Request.blank("/")
    request.authorization = ("JWT", token)
    jwt_claims = policy.get_claims(request)
    assert jwt_claims == {}


def test_algorithm_unsupported():
    policy = JWTAuthenticationPolicy("secret", algorithm="SHA1")
    with pytest.raises(NotImplementedError):
        token = policy.create_token(15, name="Jöhn", admin=True)


def test_extra_claims():
    policy = JWTAuthenticationPolicy("secret")
    token = policy.create_token(15, name="Jöhn", admin=True)
    request = Request.blank("/")
    request.authorization = ("JWT", token)
    jwt_claims = policy.get_claims(request)
    assert jwt_claims["name"] == "Jöhn"
    assert jwt_claims["admin"]


def test_wrong_auth_scheme():
    policy = JWTAuthenticationPolicy("secret")
    request = Request.blank("/")
    request.authorization = ("Other", policy.create_token(15))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) is None


def test_invalid_authorization_header():
    policy = JWTAuthenticationPolicy("secret")
    request = Request.blank("/")
    request.environ["HTTP_AUTHORIZATION"] = "token"
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) is None


def test_other_header():
    policy = JWTAuthenticationPolicy("secret", http_header="X-Token")
    request = Request.blank("/")
    request.headers["X-Token"] = policy.create_token(15)
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == 15


def test_expired_token():
    policy = JWTAuthenticationPolicy("secret", expiration=-1)
    request = Request.blank("/")
    request.authorization = ("JWT", policy.create_token(15))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) is None
    policy.leeway = 5
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == 15


def test_dynamic_expired_token():
    policy = JWTAuthenticationPolicy("secret", expiration=-1)
    request = Request.blank("/")
    request.authorization = ("JWT", policy.create_token(15, expiration=5))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == 15

    policy = JWTAuthenticationPolicy("secret")
    request.authorization = ("JWT", policy.create_token(15, expiration=-1))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) is None
    request.authorization = ("JWT", policy.create_token(15))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == 15


def test_remember_warning():
    policy = JWTAuthenticationPolicy("secret", http_header="X-Token")
    with testConfig() as config:
        config.set_authorization_policy(DummySecurityPolicy())
        config.set_authentication_policy(policy)
        request = DummyRequest()
        with warnings.catch_warnings(record=True) as w:
            remember(request, 15)
    assert len(w) == 1
    assert issubclass(w[-1].category, UserWarning)
    assert "JWT tokens" in str(w[-1].message)
    assert w[-1].filename.endswith("test_policy.py")


def test_forget_warning():
    policy = JWTAuthenticationPolicy("secret", http_header="X-Token")
    with testConfig() as config:
        config.set_authorization_policy(DummySecurityPolicy())
        config.set_authentication_policy(policy)
        request = DummyRequest()
        with warnings.catch_warnings(record=True) as w:
            forget(request)
    assert len(w) == 1
    assert issubclass(w[-1].category, UserWarning)
    assert "JWT tokens" in str(w[-1].message)
    assert w[-1].filename.endswith("test_policy.py")


def test_default_json_encoder():
    policy = JWTAuthenticationPolicy("secret")
    assert isinstance(policy.json_encoder, PyramidJSONEncoderFactory)
    assert isinstance(policy.json_encoder(), JSONEncoder)


class MyCustomJsonEncoder(JSONEncoder):
    def default(self, o):
        if type(o) is UUID:
            return str(o)
        # Let the base class default method raise the TypeError
        return JSONEncoder.default(self, o)


def test_custom_json_encoder():
    policy = JWTAuthenticationPolicy("secret")
    principal_id = uuid.uuid4()
    claim_value = uuid.uuid4()
    with pytest.raises(TypeError):
        token = policy.create_token("subject", uuid_value=claim_value)
    policy = JWTAuthenticationPolicy("secret", json_encoder=MyCustomJsonEncoder)

    request = Request.blank("/")
    request.authorization = (
        "JWT",
        policy.create_token(principal_id, uuid_value=claim_value),
    )
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == str(principal_id)
    assert request.jwt_claims.get("uuid_value") == str(claim_value)


def test_cookie_policy_creation():
    token_policy = JWTAuthenticationPolicy("secret")
    request = Request.blank("/")
    cookie_policy = JWTCookieAuthenticationPolicy.make_from(token_policy)

    headers = cookie_policy.remember(request, "user")

    assert isinstance(headers, list)
    assert len(headers) == 1


def test_cookie_policy_creation_fail():
    with pytest.raises(TypeError) as e:
        JWTCookieAuthenticationPolicy.make_from(object())

    assert "Invalid policy type" in str(e.value)


def test_cookie_policy_remember():
    policy = JWTCookieAuthenticationPolicy("secret")
    request = Request.blank("/")
    headers = policy.remember(request, "user")

    header, cookie = headers[0]
    assert header.lower() == "set-cookie"

    chunks = cookie.split("; ")
    assert chunks[0].startswith(f"{policy.cookie_name}=")

    assert "HttpOnly" in chunks
    assert "secure" in chunks


def test_cookie_policy_forget():
    policy = JWTCookieAuthenticationPolicy("secret")
    request = Request.blank("/")
    headers = policy.forget(request)

    header, cookie = headers[0]
    assert header.lower() == "set-cookie"

    chunks = cookie.split("; ")
    cookie_values = [c for c in chunks if "=" in c]
    assert cookie_values[0].startswith(f"{policy.cookie_name}=")

    assert "Max-Age=0" in chunks
    assert hasattr(request, "_jwt_cookie_reissue_revoked")


def test_cookie_policy_custom_domain_list():
    policy = JWTCookieAuthenticationPolicy("secret")
    request = Request.blank("/")
    domains = [request.domain, "other"]
    headers = policy.remember(request, "user", domains=domains)

    assert len(headers) == 2
    _, cookie1 = headers[0]
    _, cookie2 = headers[1]

    assert f"Domain={request.domain}" in cookie1
    assert f"Domain=other" in cookie2


def test_insecure_cookie_policy():
    policy = JWTCookieAuthenticationPolicy("secret", https_only=False)
    request = Request.blank("/")
    headers = policy.forget(request)

    _, cookie = headers[0]
    chunks = cookie.split("; ")

    assert "secure" not in chunks


def test_insecure_cookie_policy():
    policy = JWTCookieAuthenticationPolicy("secret", https_only=False)
    request = Request.blank("/")
    headers = policy.forget(request)

    _, cookie = headers[0]
    chunks = cookie.split("; ")

    assert "secure" not in chunks


@pytest.mark.freeze_time
def test_cookie_policy_max_age():
    expiry = timedelta(seconds=10)
    policy = JWTCookieAuthenticationPolicy("secret", expiration=expiry)
    request = Request.blank("/")
    headers = policy.forget(request)

    _, cookie = headers[0]
    chunks = cookie.split("; ")

    assert "Max-Age=10" not in chunks
