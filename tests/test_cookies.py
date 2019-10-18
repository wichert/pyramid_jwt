import uuid

from pyramid.interfaces import IAuthenticationPolicy
from webob import Request
from zope.interface.verify import verifyObject

from pyramid_jwt.policy import JWTTokenAuthenticationPolicy


def test_interface():
    verifyObject(IAuthenticationPolicy, JWTTokenAuthenticationPolicy('secret'))


def test_cookie():
    policy = JWTTokenAuthenticationPolicy('secret')
    request = Request.blank('/')
    cookie = policy.remember(request, str(uuid.uuid4())).pop()

    assert len(cookie) == 2

    header, cookie = cookie
    assert header == 'Set-Cookie'
    assert len(cookie) > 0


def test_cookie_name():
    policy = JWTTokenAuthenticationPolicy('secret', cookie_name='auth')
    request = Request.blank('/')
    _, cookie = policy.remember(request, str(uuid.uuid4())).pop()

    name, value = cookie.split('=', 1)
    assert name == 'auth'


def test_secure_cookie():
    policy = JWTTokenAuthenticationPolicy('secret', https_only=True)
    request = Request.blank('/')
    _, cookie = policy.remember(request, str(uuid.uuid4())).pop()

    assert '; secure;' in cookie
    assert '; HttpOnly' in cookie


def test_insecure_cookie():
    policy = JWTTokenAuthenticationPolicy('secret', https_only=False)
    request = Request.blank('/')
    _, cookie = policy.remember(request, str(uuid.uuid4())).pop()

    assert '; secure;' not in cookie
    assert '; HttpOnly' in cookie


def test_cookie_decode():
    policy = JWTTokenAuthenticationPolicy('secret', https_only=False)
    request = Request.blank('/')

    principal = str(uuid.uuid4())
    header, cookie = policy.remember(request, principal).pop()
    name, value = cookie.split('=', 1)
    request.cookies = {name: value.split(';', 1)[0]}

    claims = policy.get_claims(request)
    assert claims['sub'] == principal
