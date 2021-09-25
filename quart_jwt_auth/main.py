import jwt
from uuid import uuid4
from quart import current_app
import arrow, datetime


class JWTAuth(object):
    '''
    An object used to hold JWT settings for the
    Quart-GraphQL-Auth extension.

    Instances of :class:`JWTAuth` are *not* bound to specific apps, so
    you can create one in the main body of your code and then bind it
    to your app in a factory function.
    '''

    def __init__(self, app=None):
        '''
        Create the JWTAuth instance. You can either pass a quart application in directly
        here to register this extension with the quart app, or call init_app after creating
        this object (in a factory pattern).
        :param app: A quart application
        '''
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        '''
        Register this extension with the quart app.

        :param app: A quart application
        '''
        # Save this so we can use it later in the extension
        if not hasattr(app, 'extensions'):  # pragma: no cover
            app.extensions = {}
        app.extensions['quart-jwt-auth'] = self

        self._set_default__configuration_options(app)

    @staticmethod
    def _set_default__configuration_options(app):
        '''
        Sets the default configuration options used by this extension
        '''
        app.config.setdefault(
            'JWT_TOKEN_ARGUMENT_NAME', 'auth_token'
        )
        app.config.setdefault(
            'JWT_AUTH_TOKEN_EXPIRES', arrow.utcnow().shift(days=+365).timestamp
        )
        app.config.setdefault(
            'JWT_SECRET_KEY', None
        )
        app.config.setdefault(
            'JWT_PRIV_KEY', None
        )
        app.config.setdefault(
            'JWT_PUB_KEY', None
        )
        app.config.setdefault(
            'JWT_IDENTITY_CLAIM', 'public_id'
        )
        app.config.setdefault(
            'JWT_USER_CLAIMS', 'user_claims'
        )
        app.config.setdefault(
            'JWT_COOKIE_NAME', 'cereal-x-access-token'
        )
        app.config.setdefault(
            'JWT_COOKIE_TOKEN_PREFIX', 'CAT='
        )

    @staticmethod
    def _create_basic_token_data(public_id, valid):
        uid = str(uuid4())
        now = arrow.utcnow().datetime

        token_data = {
            'valid': valid,
            'iat': now,
            'nbf': now,
            'jti': uid,
            current_app.config['JWT_IDENTITY_CLAIM']: public_id,
        }

        exp = current_app.config['JWT_AUTH_TOKEN_EXPIRES']
        if isinstance(exp, int):
            exp = datetime.timedelta(minutes=exp)

        token_data.update({'exp': now + exp})

        return token_data

    def _create_auth_token(self, public_id, valid, user_claims):
        token_data = self._create_basic_token_data(
            public_id=public_id,
            valid=valid
        )

        if user_claims:
            if not isinstance(user_claims, dict):
                raise TypeError('User claim should be dictionary type.')

            token_data.update({current_app.config['JWT_USER_CLAIMS']: user_claims})

        return jwt.encode(
            payload=token_data,
            key=current_app.config['JWT_PRIV_KEY'],
            algorithm='RS512',
            json_encoder=current_app.json_encoder,
        )#.decode('utf-8')
