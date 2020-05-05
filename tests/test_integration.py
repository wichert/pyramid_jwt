import pytest
from pyramid.config import Configurator
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.renderers import JSON
from pyramid.security import Authenticated
from pyramid.security import Allow
from webtest import TestApp


def login_view(request):
    return {"token": request.create_jwt_token(1)}


def secure_view(request):
    return "OK"


def dump_claims(request):
    return request.jwt_claims


class Root:
    __acl__ = [
        (Allow, Authenticated, ("read",)),
    ]

    def __init__(self, request):
        pass


class NonSerializable(object):
    pass


class Serializable(object):
    def __json__(self):
        return "This is JSON Serializable"


def extra_claims(request):
    return {
        "token": request.create_jwt_token(
            principal=1, extra_claim=NonSerializable()
        )
    }


@pytest.fixture(scope="module")
def app_config() -> Configurator:
    config = Configurator()
    config.set_authorization_policy(ACLAuthorizationPolicy())
    # Enable JWT authentication.
    config.include("pyramid_jwt")
    config.set_root_factory(Root)
    config.set_jwt_authentication_policy("secret", http_header="X-Token")
    config.add_route("login", "/login")
    config.add_view(login_view, route_name="login", renderer="json")
    config.add_route("secure", "/secure")
    config.add_view(
        secure_view, route_name="secure", renderer="string", permission="read"
    )
    config.add_route("extra_claims", "/extra_claims")
    config.add_view(extra_claims, route_name="extra_claims", renderer="json")
    config.add_route("dump_claims", "/dump_claims")
    config.add_view(
        dump_claims, route_name="dump_claims", renderer="json", permission="read"
    )
    return config


@pytest.fixture
def app(app_config):
    app = app_config.make_wsgi_app()
    return TestApp(app)


def test_secure_view_requires_auth(app):
    app.get("/secure", status=403)


def test_login(app):
    r = app.get("/login")
    token = str(r.json_body["token"])  # Must be str on all Python versions
    r = app.get("/secure", headers={"X-Token": token})
    assert r.unicode_body == "OK"


def test_pyramid_json_encoder_fail(app):
    with pytest.raises(TypeError) as e:
        app.get("/extra_claims")

    assert "NonSerializable" in str(e.value)
    assert "is not JSON serializable" in str(e.value)


def test_pyramid_json_encoder_with_adapter(app):
    """Test we can define a custom adapter using global json_renderer_factory"""
    from pyramid.renderers import json_renderer_factory

    def serialize_anyclass(obj, request):
        return obj.__class__.__name__
    json_renderer_factory.add_adapter(NonSerializable, serialize_anyclass)

    response = app.get("/extra_claims")
    token = str(response.json_body["token"])

    response = app.get("/dump_claims", headers={"X-Token": token})
    assert response.json_body['extra_claim'] == 'NonSerializable'


def test_pyramid_custom_json_encoder(app_config: Configurator):
    """Test we can still use user-defined custom adapter"""
    from pyramid.renderers import json_renderer_factory

    def serialize_anyclass(obj, request):
        assert False  # This asserts this method will not be called
    json_renderer_factory.add_adapter(NonSerializable, serialize_anyclass)

    def other_serializer(obj, request):
        return "other_serializer"

    my_renderer = JSON()
    my_renderer.add_adapter(NonSerializable, other_serializer)
    app_config.add_renderer('json', my_renderer)
    app = TestApp(app_config.make_wsgi_app())

    response = app.get("/extra_claims")
    token = str(response.json_body["token"])

    response = app.get("/dump_claims", headers={"X-Token": token})
    assert response.json_body['extra_claim'] == 'other_serializer'
