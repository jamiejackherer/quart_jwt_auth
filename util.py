from quart import current_app, _app_ctx_stack as ctx_stack


def _get_jwt_manager():
    try:
        return current_app.extensions['quart-jwt-auth']
    except KeyError:  # pragma: no cover
        raise RuntimeError(
            'You must initialize a JWTManager with this quart '
            'application before using this method'
        )


def create_auth_token(public_id, valid=True, user_claims=None):
    '''
    Create a new access token.

    :param public_id: The identity of this token, which can be any data that is
                     json serializable. It can also be a python object
    :param user_claims: User made claims that will be added to this token. it
                        should be dictionary.

    :return: An encoded access token
    '''
    jwt_manager = _get_jwt_manager()
    return jwt_manager._create_auth_token(public_id, valid, user_claims)


def get_raw_jwt():
    '''
    In a protected view, this will return the python dictionary which has
    all of the claims of the JWT that is accessing the endpoint. If no
    JWT is currently present, an empty dict is returned instead.
    '''
    return getattr(ctx_stack.top, 'jwt', {})


def get_jwt_identity():
    '''
    In a protected view, this will return the identity of the JWT that is
    accessing this endpoint. If no JWT is present, `None` is returned instead.
    '''
    return get_raw_jwt().get(current_app.config['JWT_IDENTITY_CLAIM'], None)


def get_jwt_claims():
    '''
    In a protected view, this will return the dictionary of custom claims
    in the JWT that is accessing the endpoint. If no custom user claims are
    present, an empty dict is returned instead.
    '''
    return get_raw_jwt().get(current_app.config['JWT_USER_CLAIMS'], {})
