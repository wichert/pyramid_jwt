from .policy import (
    JWTAuthenticationPolicy,
    JWTCookieAuthenticationPolicy,
    json_encoder_factory,
)


def includeme(config):
    json_encoder_factory.registry = config.registry
    config.add_directive(
        "set_jwt_authentication_policy", set_jwt_authentication_policy, action_wrap=True
    )
    config.add_directive(
        "set_jwt_cookie_authentication_policy",
        set_jwt_cookie_authentication_policy,
        action_wrap=True,
    )


def create_jwt_authentication_policy(
    config,
    private_key=None,
    public_key=None,
    algorithm=None,
    expiration=None,
    leeway=None,
    http_header=None,
    auth_type=None,
    callback=None,
    json_encoder=None,
    audience=None,
):
    settings = config.get_settings()
    private_key = private_key or settings.get("jwt.private_key")
    audience = audience or settings.get("jwt.audience")
    algorithm = algorithm or settings.get("jwt.algorithm") or "HS512"
    if not algorithm.startswith("HS"):
        public_key = public_key or settings.get("jwt.public_key")
    else:
        public_key = None
    if expiration is None and "jwt.expiration" in settings:
        expiration = int(settings.get("jwt.expiration"))
    leeway = int(settings.get("jwt.leeway", 0)) if leeway is None else leeway
    http_header = http_header or settings.get("jwt.http_header") or "Authorization"
    if http_header.lower() == "authorization":
        auth_type = auth_type or settings.get("jwt.auth_type") or "JWT"
    else:
        auth_type = None
    return JWTAuthenticationPolicy(
        private_key=private_key,
        public_key=public_key,
        algorithm=algorithm,
        leeway=leeway,
        expiration=expiration,
        http_header=http_header,
        auth_type=auth_type,
        callback=callback,
        json_encoder=json_encoder,
        audience=audience,
    )


def _request_create_token(request, principal, expiration=None, audience=None, **claims):

    return request.authentication_policy.create_token(
        principal, expiration, audience, **claims
    )


def _request_claims(request):
    return request.authentication_policy.get_claims(request)


def _configure(config, auth_policy):
    config.set_authentication_policy(auth_policy)
    config.add_request_method(
        lambda request: auth_policy, "authentication_policy", reify=True
    )
    config.add_request_method(_request_claims, "jwt_claims", reify=True)
    config.add_request_method(_request_create_token, "create_jwt_token")


def set_jwt_cookie_authentication_policy(
    config,
    private_key=None,
    public_key=None,
    algorithm=None,
    expiration=None,
    leeway=None,
    http_header=None,
    auth_type=None,
    callback=None,
    json_encoder=None,
    audience=None,
    cookie_name=None,
    https_only=True,
    samesite=None,
    reissue_time=None,
    cookie_path=None,
):
    settings = config.get_settings()
    cookie_name = cookie_name or settings.get("jwt.cookie_name")
    cookie_path = cookie_path or settings.get("jwt.cookie_path")
    reissue_time = reissue_time or settings.get("jwt.cookie_reissue_time")
    if https_only is None:
        https_only = settings.get("jwt.https_only_cookie", True)
    if samesite is None:
        samesite = settings.get("jwt.samesite", None)

    auth_policy = create_jwt_authentication_policy(
        config,
        private_key,
        public_key,
        algorithm,
        expiration,
        leeway,
        http_header,
        auth_type,
        callback,
        json_encoder,
        audience,
    )

    auth_policy = JWTCookieAuthenticationPolicy.make_from(
        auth_policy,
        cookie_name=cookie_name,
        https_only=https_only,
        reissue_time=reissue_time,
        cookie_path=cookie_path,
    )

    _configure(config, auth_policy)


def set_jwt_authentication_policy(
    config,
    private_key=None,
    public_key=None,
    algorithm=None,
    expiration=None,
    leeway=None,
    http_header=None,
    auth_type=None,
    callback=None,
    json_encoder=None,
    audience=None,
):
    policy = create_jwt_authentication_policy(
        config,
        private_key,
        public_key,
        algorithm,
        expiration,
        leeway,
        http_header,
        auth_type,
        callback,
        json_encoder,
        audience,
    )

    _configure(config, policy)
