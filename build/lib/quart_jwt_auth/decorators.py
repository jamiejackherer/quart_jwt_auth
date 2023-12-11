from quart import _app_ctx_stack as ctx_stack, current_app, request
from functools import wraps
import jwt
from quart_login import current_user

from .exceptions import *


def decode_jwt(token, key, identity_claim_key, user_claims_key):
    '''
    Decodes an encoded JWT

    :param jwt: The encoded JWT string to decode
    :param pub_key: The public key for decryption
    :param identity_claim_key: expected key that contains the identity
    :param user_claims_key: expected key that contains the user claims
    :return: Dictionary containing contents of the JWT
    '''
    # This call verifies the ext, iat, and nbf claims
    jwt_data = jwt.decode(
        jwt=token,
        key=key,
        algorithms=['RS512']
    )

    # Make sure that any custom claims we expect in the token are present

    if 'jti' not in jwt_data:
        raise JWTDecodeError('Missing claim: jti')
    if identity_claim_key not in jwt_data:
        raise JWTDecodeError(f'Missing claim: {identity_claim_key}')
    if user_claims_key not in jwt_data:
        jwt_data[user_claims_key] = {}

    return jwt_data


def get_jwt_data(token):
    '''
    Decodes encoded JWT token by using extension setting and validates token type

    :param jwt: The encoded JWT string to decode
    :return: Dictionary containing contents of the JWT
    '''
    jwt_data = decode_jwt(
        token=token,
        key=current_app.config['JWT_PUB_KEY'],
        identity_claim_key=current_app.config['JWT_IDENTITY_CLAIM'],
        user_claims_key=current_app.config['JWT_USER_CLAIMS'],
    )

    # token validity verification
    if not jwt_data['valid']:
        raise InvalidTokenError('The token has been invalidated.')

    return jwt_data


def verify_jwt_cookie(cookie_token):
    '''
    Verify access tokens in headers and cookie match

    :param cookie_token: The encoded cookie JWT string to decode
    :return: Dictionary containing contents of the JWT
    '''
    cookie_jwt_data = get_jwt_data(cookie_token)
    if cookie_jwt_data is not None:
        return True
    return False


def verify_jwt_in_argument(token):
    '''
    Verify access token

    :param jwt: The encoded JWT string to decode
    :return: Dictionary containing contents of the JWT
    '''
    ctx_stack.top.jwt = get_jwt_data(token)


def _extract_header_token_value(request_headers):
    '''
    Extract token value from the request headers.

    It uses the token found in the header specified in the
    JWT_COOKIE_NAME configuration variable and requires
    the token to have the prefix specified in the
    JWT_COOKIE_TOKEN_PREFIX variable

    :param request_headers: Request headers as dict
    :return: Token value as a string (None if token is not found)
    '''
    authorization_header = request_headers[current_app.config['JWT_COOKIE_NAME']]
    token_prefix = current_app.config['JWT_COOKIE_TOKEN_PREFIX'].lower()
    if authorization_header and authorization_header.lower().startswith(token_prefix):
        return authorization_header.split('=')[-1]
    return None


def _extract_cookie_token_value(request_cookies):
    '''
    Extract token value from the request cookies.

    It uses the token found in the cookie specified in the
    JWT_COOKIE_NAME configuration variable and requires
    the token to have the prefix specified in the
    JWT_COOKIE_TOKEN_PREFIX variable

    :param request_cookies: Request cookies as dict
    :return: Token value as a string (None if token is not found)
    '''
    authorization_cookie = request_cookies[current_app.config['JWT_COOKIE_NAME']]
    if authorization_cookie and authorization_cookie.startswith(current_app.config['JWT_COOKIE_TOKEN_PREFIX']):
        return authorization_cookie.split('=')[-1]
    return None

def jwt_required(fn):
    '''
    A decorator to protect a view.

    If you decorate an view with this, it will ensure that the requester
    has a valid auth token before allowing the resolver to be called.
    '''

    @wraps(fn)
    def wrapper(*args, **kwargs):
        #print(f'jwt_required request.cookies::: {request.cookies}')
        cookie_token = None
        if current_app.config['JWT_COOKIE_NAME'] in request.cookies:
            cookie_token = _extract_cookie_token_value(request.cookies)
            #print(f'jwt_required cookie_token::: {cookie_token}')
        # print(f'cookie_token token::: {cookie_token}')
        if not cookie_token:
            return 'Cookie token is missing!'
        if not verify_jwt_cookie(cookie_token):
            return f'verify_jwt_cookie failed'
        
        #current_u = current_user
        return fn(*args, **kwargs)

    return wrapper


def login_required(func):
    '''
    If you decorate a view with this, it will ensure that the current user is
    logged in and authenticated before calling the actual view. (If they are
    not, it calls the :attr:`LoginManager.unauthorized` callback.) For
    example::
        @app.route('/post')
        @login_required
        def post():
            pass
    If there are only certain times you need to require that your user is
    logged in, you can do so with::
        if not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()
    ...which is essentially the code that this function adds to your views.
    It can be convenient to globally turn off authentication when unit testing.
    To enable this, if the application configuration variable `LOGIN_DISABLED`
    is set to `True`, this decorator will be ignored.
    .. Note ::
        Per `W3 guidelines for CORS preflight requests
        <http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0>`_,
        HTTP ``OPTIONS`` requests are exempt from login checks.
    :param func: The view function to decorate.
    :type func: function
    '''
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if request.method in set(['OPTIONS']):
            return func(*args, **kwargs)
        elif current_app.config.get('LOGIN_DISABLED'):
            return func(*args, **kwargs)
        elif not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()
        return func(*args, **kwargs)
    return decorated_view


