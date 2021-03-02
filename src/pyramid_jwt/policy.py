import datetime
import logging
import time
import warnings
from json import JSONEncoder

import jwt
from pyramid.renderers import JSON
from webob.cookies import CookieProfile
from zope.interface import implementer
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.interfaces import IAuthenticationPolicy, IRendererFactory

log = logging.getLogger("pyramid_jwt")
marker = []


class PyramidJSONEncoderFactory(JSON):
    def __init__(self, pyramid_registry=None, **kw):
        super().__init__(**kw)
        self.registry = pyramid_registry

    def __call__(self, *args, **kwargs):
        json_renderer = None
        if self.registry is not None:
            json_renderer = self.registry.queryUtility(
                IRendererFactory, "json", default=JSONEncoder
            )

        request = kwargs.get("request")
        if not kwargs.get("default") and isinstance(json_renderer, JSON):
            self.components = json_renderer.components
            kwargs["default"] = self._make_default(request)
        return JSONEncoder(*args, **kwargs)


json_encoder_factory = PyramidJSONEncoderFactory(None)


@implementer(IAuthenticationPolicy)
class JWTAuthenticationPolicy(CallbackAuthenticationPolicy):
    def __init__(
        self,
        private_key,
        public_key=None,
        algorithm="HS512",
        leeway=0,
        expiration=None,
        default_claims=None,
        http_header="Authorization",
        auth_type="JWT",
        callback=None,
        json_encoder=None,
        audience=None,
    ):
        self.private_key = private_key
        self.public_key = public_key if public_key is not None else private_key
        self.algorithm = algorithm
        self.leeway = leeway
        self.default_claims = default_claims if default_claims else {}
        self.http_header = http_header
        self.auth_type = auth_type
        if expiration:
            if not isinstance(expiration, datetime.timedelta):
                expiration = datetime.timedelta(seconds=expiration)
            self.expiration = expiration
        else:
            self.expiration = None
        if audience:
            self.audience = audience
        else:
            self.audience = None
        self.callback = callback
        if json_encoder is None:
            json_encoder = json_encoder_factory
        self.json_encoder = json_encoder
        self.jwt_std_claims = ("sub", "iat", "exp", "aud")

    def create_token(self, principal, expiration=None, audience=None, **claims):
        payload = self.default_claims.copy()
        payload.update(claims)
        payload["sub"] = principal
        payload["iat"] = iat = datetime.datetime.utcnow()
        expiration = expiration or self.expiration
        audience = audience or self.audience
        if expiration:
            if not isinstance(expiration, datetime.timedelta):
                expiration = datetime.timedelta(seconds=expiration)
            payload["exp"] = iat + expiration
        if audience:
            payload["aud"] = audience
        token = jwt.encode(
            payload,
            self.private_key,
            algorithm=self.algorithm,
            json_encoder=self.json_encoder,
        )
        if not isinstance(token, str):  # Python3 unicode madness
            token = token.decode("ascii")
        return token

    def get_claims(self, request):
        if self.http_header == "Authorization":
            try:
                if request.authorization is None:
                    return {}
            except ValueError:  # Invalid Authorization header
                return {}
            (auth_type, token) = request.authorization
            if auth_type != self.auth_type:
                return {}
        else:
            token = request.headers.get(self.http_header)
        if not token:
            return {}
        return self.jwt_decode(request, token)

    def jwt_decode(self, request, token):
        try:
            claims = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                leeway=self.leeway,
                audience=self.audience,
            )
            return claims
        except jwt.InvalidTokenError as e:
            log.warning("Invalid JWT token from %s: %s", request.remote_addr, e)
            return {}

    def unauthenticated_userid(self, request):
        return request.jwt_claims.get("sub")

    def remember(self, request, principal, **kw):
        warnings.warn(
            "JWT tokens need to be returned by an API. Using remember() "
            "has no effect.",
            stacklevel=3,
        )
        return []

    def forget(self, request):
        warnings.warn(
            "JWT tokens are managed by API (users) manually. Using forget() "
            "has no effect.",
            stacklevel=3,
        )
        return []


class ReissueError(Exception):
    pass


@implementer(IAuthenticationPolicy)
class JWTCookieAuthenticationPolicy(JWTAuthenticationPolicy):
    def __init__(
        self,
        private_key,
        public_key=None,
        algorithm="HS512",
        leeway=0,
        expiration=None,
        default_claims=None,
        http_header="Authorization",
        auth_type="JWT",
        callback=None,
        json_encoder=None,
        audience=None,
        cookie_name=None,
        https_only=True,
        samesite=None,
        reissue_time=None,
        cookie_path=None,
    ):
        super(JWTCookieAuthenticationPolicy, self).__init__(
            private_key,
            public_key,
            algorithm,
            leeway,
            expiration,
            default_claims,
            http_header,
            auth_type,
            callback,
            json_encoder,
            audience,
        )

        self.https_only = https_only
        self.samesite = samesite
        self.cookie_name = cookie_name or "Authorization"
        self.max_age = self.expiration and self.expiration.total_seconds()

        if reissue_time and isinstance(reissue_time, datetime.timedelta):
            reissue_time = reissue_time.total_seconds()
        self.reissue_time = reissue_time

        self.cookie_profile = CookieProfile(
            cookie_name=self.cookie_name,
            secure=self.https_only,
            samesite=self.samesite,
            max_age=self.max_age,
            httponly=True,
            path=cookie_path,
        )

    @staticmethod
    def make_from(policy, **kwargs):
        if not isinstance(policy, JWTAuthenticationPolicy):
            pol_type = policy.__class__.__name__
            raise ValueError("Invalid policy type %s" % pol_type)

        return JWTCookieAuthenticationPolicy(
            private_key=policy.private_key,
            public_key=policy.public_key,
            algorithm=policy.algorithm,
            leeway=policy.leeway,
            expiration=policy.expiration,
            default_claims=policy.default_claims,
            http_header=policy.http_header,
            auth_type=policy.auth_type,
            callback=policy.callback,
            json_encoder=policy.json_encoder,
            audience=policy.audience,
            **kwargs
        )

    def _get_cookies(self, request, value, max_age=None, domains=None):
        profile = self.cookie_profile(request)
        if domains is None:
            domains = [request.domain]

        kw = {"domains": domains}
        if max_age is not None:
            kw["max_age"] = max_age

        headers = profile.get_headers(value, **kw)
        return headers

    def remember(self, request, principal, **kw):
        token = self.create_token(principal, self.expiration, self.audience, **kw)

        if hasattr(request, "_jwt_cookie_reissued"):
            request._jwt_cookie_reissue_revoked = True

        domains = kw.get("domains")

        return self._get_cookies(request, token, self.max_age, domains=domains)

    def forget(self, request):
        request._jwt_cookie_reissue_revoked = True
        return self._get_cookies(request, None)

    def get_claims(self, request):
        profile = self.cookie_profile.bind(request)
        cookie = profile.get_value()

        reissue = self.reissue_time is not None

        if cookie is None:
            return {}

        claims = self.jwt_decode(request, cookie)

        if reissue and not hasattr(request, "_jwt_cookie_reissued"):
            self._handle_reissue(request, claims)
        return claims

    def _handle_reissue(self, request, claims):
        if not request or not claims:
            raise ValueError("Cannot handle JWT reissue: insufficient arguments")

        if "iat" not in claims:
            raise ReissueError("Token claim's is missing IAT")
        if "sub" not in claims:
            raise ReissueError("Token claim's is missing SUB")

        token_dt = claims["iat"]
        principal = claims["sub"]
        now = time.time()

        if now < token_dt + self.reissue_time:
            # Token not yet eligible for reissuing
            return

        extra_claims = dict(
            filter(lambda item: item[0] not in self.jwt_std_claims, claims.items())
        )
        headers = self.remember(request, principal, **extra_claims)

        def reissue_jwt_cookie(request, response):
            if not hasattr(request, "_jwt_cookie_reissue_revoked"):
                for k, v in headers:
                    response.headerlist.append((k, v))

        request.add_response_callback(reissue_jwt_cookie)
        request._jwt_cookie_reissued = True
