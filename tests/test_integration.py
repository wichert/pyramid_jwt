import pytest
from pyramid.config import Configurator
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.security import Authenticated
from pyramid.security import Allow
from webtest import TestApp


def login_view(request):
    return {'token': request.create_jwt_token(1)}


def secure_view(_):
    return 'OK'


class Root:
    __acl__ = [
        (Allow, Authenticated, ('read',)),
    ]

    def __init__(self, _):
        pass


@pytest.fixture
def app():
    config = Configurator()
    config.set_authorization_policy(ACLAuthorizationPolicy())
    # Enable JWT authentication.
    config.include('pyramid_jwt')
    config.set_root_factory(Root)
    config.set_jwt_authentication_policy('secret', http_header='X-Token')
    config.add_route('login', '/login')
    config.add_view(login_view, route_name='login', renderer='json')
    config.add_route('secure', '/secure')
    config.add_view(secure_view, route_name='secure', renderer='string',
                    permission='read')
    app = config.make_wsgi_app()
    return TestApp(app)


def test_secure_view_requires_auth(app):
    app.get('/secure', status=403)


def test_login(app):
    r = app.get('/login')
    token = str(r.json_body['token'])  # Must be str on all Python versions
    r = app.get('/secure', headers={'X-Token': token})
    assert r.unicode_body == 'OK'
