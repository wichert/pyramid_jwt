from .policy import JWTAuthenticationPolicy


def includeme(config):
    config.add_directive(
        'set_jwt_authentication_policy',
        set_jwt_authentication_policy,
        action_wrap=True)


def create_jwt_authentication_policy(config, private_key=None, public_key=None,
        algorithm=None, expiration=None, leeway=None,
        http_header=None, auth_type=None, callback=None):
    settings = config.get_settings()
    private_key = private_key or settings.get('jwt.private_key')
    algorithm = algorithm or settings.get('jwt.algorithm') or 'HS512'
    if algorithm.startswith('RS') or algorithm.startswith('EC'):
            public_key = public_key or settings.get('jwt.public_key')
    else:
            public_key = None
    if expiration is None and 'jwt.expiration' in settings:
        expiration = int(settings.get('jwt.expiration'))
    leeway = int(settings.get('jwt.leeway', 0)) if leeway is None else leeway
    http_header = http_header or settings.get('jwt.http_header') or 'Authorization'
    if http_header.lower() == 'authorization':
            auth_type = auth_type or settings.get('jwt.auth_type') or 'JWT'
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
            callback=callback)


def set_jwt_authentication_policy(config, private_key=None, public_key=None,
        algorithm=None, expiration=None, leeway=None,
        http_header=None, auth_type=None, callback=None):
    policy = create_jwt_authentication_policy(
            config, private_key, public_key,
            algorithm, expiration, leeway,
            http_header, auth_type, callback)

    def request_create_token(request, principal, expiration=None, **claims):
            return policy.create_token(principal, expiration, **claims)

    config.set_authentication_policy(policy)
    config.add_request_method(request_create_token, 'create_jwt_token')
