class JWTExtendedException(Exception):
    """
    Base except which all flask_jwt_auth errors extend
    """
    pass


class JWTDecodeError(JWTExtendedException):
    """
    An error decoding a JWT
    """
    pass


class NoAuthorizationError(JWTExtendedException):
    """
    An error raised when no authorization token was found in a protected view.
    """
    pass


class RevokedTokenError(JWTExtendedException):
    """
    Error raised when a revoked token attempt to access a protected view.
    """
    pass


class InvalidTokenError(JWTExtendedException):
    """
    Error raised when a token that has been invalidated attempts to access a protected view.
    """
    pass
