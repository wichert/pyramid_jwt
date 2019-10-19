# vim: fileencoding=utf-8
import warnings
from webob import Request
from zope.interface.verify import verifyObject
from pyramid.security import forget
from pyramid.security import remember
from pyramid.testing import testConfig
from pyramid.testing import DummyRequest
from pyramid.testing import DummySecurityPolicy
from pyramid.interfaces import IAuthenticationPolicy
from pyramid_jwt.policy import JWTAuthenticationPolicy
import uuid
import pytest
from json.encoder import JSONEncoder
from uuid import UUID


def test_interface():
    verifyObject(IAuthenticationPolicy, JWTAuthenticationPolicy('secret'))


def test_token_most_be_str():
    policy = JWTAuthenticationPolicy('secret')
    token = policy.create_token(15)
    assert isinstance(token, str)


def test_minimal_roundtrip():
    policy = JWTAuthenticationPolicy('secret')
    request = Request.blank('/')
    request.authorization = ('JWT', policy.create_token(15))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == 15


def test_audience_valid():
    policy = JWTAuthenticationPolicy('secret', audience='example.org')
    token = policy.create_token(15, name=u'Jöhn', admin=True,
                                audience='example.org')
    request = Request.blank('/')
    request.authorization = ('JWT', token)
    jwt_claims = policy.get_claims(request)
    assert jwt_claims['aud'] == 'example.org'


def test_audience_invalid():
    policy = JWTAuthenticationPolicy('secret', audience='example.org')
    token = policy.create_token(15, name=u'Jöhn', admin=True,
                                audience='example.com')
    request = Request.blank('/')
    request.authorization = ('JWT', token)
    jwt_claims = policy.get_claims(request)
    assert jwt_claims == {}


def test_algorithm_unsupported():
    policy = JWTAuthenticationPolicy('secret', algorithm='SHA1')
    with pytest.raises(NotImplementedError):
        policy.create_token(15, name=u'Jöhn', admin=True)


def test_extra_claims():
    policy = JWTAuthenticationPolicy('secret')
    token = policy.create_token(15, name=u'Jöhn', admin=True)
    request = Request.blank('/')
    request.authorization = ('JWT', token)
    jwt_claims = policy.get_claims(request)
    assert jwt_claims['name'] == u'Jöhn'
    assert jwt_claims['admin']


def test_wrong_auth_scheme():
    policy = JWTAuthenticationPolicy('secret')
    request = Request.blank('/')
    request.authorization = ('Other', policy.create_token(15))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) is None


def test_invalid_authorization_header():
    policy = JWTAuthenticationPolicy('secret')
    request = Request.blank('/')
    request.environ['HTTP_AUTHORIZATION'] = 'token'
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) is None


def test_other_header():
    policy = JWTAuthenticationPolicy('secret', http_header='X-Token')
    request = Request.blank('/')
    request.headers['X-Token'] = policy.create_token(15)
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == 15


def test_expired_token():
    policy = JWTAuthenticationPolicy('secret', expiration=-1)
    request = Request.blank('/')
    request.authorization = ('JWT', policy.create_token(15))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) is None
    policy.leeway = 5
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == 15


def test_dynamic_expired_token():
    policy = JWTAuthenticationPolicy('secret', expiration=-1)
    request = Request.blank('/')
    request.authorization = ('JWT', policy.create_token(15, expiration=5))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == 15

    policy = JWTAuthenticationPolicy('secret')
    request.authorization = ('JWT', policy.create_token(15, expiration=-1))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) is None
    request.authorization = ('JWT', policy.create_token(15))
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == 15


def test_remember_warning():
    policy = JWTAuthenticationPolicy('secret', http_header='X-Token')
    with testConfig() as config:
        config.set_authorization_policy(DummySecurityPolicy())
        config.set_authentication_policy(policy)
        request = DummyRequest()
        with warnings.catch_warnings(record=True) as w:
            remember(request, 15)
    assert len(w) == 1
    assert issubclass(w[-1].category, UserWarning)
    assert 'JWT tokens' in str(w[-1].message)
    assert w[-1].filename.endswith('test_policy.py')


def test_forget_warning():
    policy = JWTAuthenticationPolicy('secret', http_header='X-Token')
    with testConfig() as config:
        config.set_authorization_policy(DummySecurityPolicy())
        config.set_authentication_policy(policy)
        request = DummyRequest()
        with warnings.catch_warnings(record=True) as w:
            forget(request)
    assert len(w) == 1
    assert issubclass(w[-1].category, UserWarning)
    assert 'JWT tokens' in str(w[-1].message)
    assert w[-1].filename.endswith('test_policy.py')


class MyCustomJsonEncoder(JSONEncoder):

    def default(self, o):
        if type(o) is UUID:
            return str(o)
        # Let the base class default method raise the TypeError
        return JSONEncoder.default(self, o)


def test_custom_json_encoder():
    policy = JWTAuthenticationPolicy('secret')
    principal_id = uuid.uuid4()
    claim_value = uuid.uuid4()
    with pytest.raises(TypeError):
        policy.create_token('subject', uuid_value=claim_value)
    policy = JWTAuthenticationPolicy(
        'secret', json_encoder=MyCustomJsonEncoder)

    request = Request.blank('/')
    request.authorization = ('JWT', policy.create_token(
        principal_id, uuid_value=claim_value)
    )
    request.jwt_claims = policy.get_claims(request)
    assert policy.unauthenticated_userid(request) == str(principal_id)
    assert request.jwt_claims.get('uuid_value') == str(claim_value)
