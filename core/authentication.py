import datetime

import jwt
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header

from core.models import User


class JWTAuthentication(BaseAuthentication):

    def authenticate(self, request):
        # Split auth string
        auth = get_authorization_header(request).split()

        # Get the access_token
        if auth and len(auth) == 2:
            # Convert to utf-8 string
            token = auth[1].decode('utf-8')
            # Decode access token
            id = decode_access_token(token)

            # Get user by id
            user = User.objects.get(pk=id)

            return (user, None)
        
        raise exceptions.AuthenticationFailed("unauthenticated")


def create_access_token(id):
    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        'iat': datetime.datetime.utcnow()
    }, 'access_secret', algorithm='HS256')


def decode_access_token(token):
    try:
        payload = jwt.decode(token, 'access_secret', algorithms='HS256')

        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed("unauthenticated")


def create_refresh_token(id):
    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }, 'refresh_secret', algorithm='HS256')

def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, 'refresh_secret', algorithms='HS256')

        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed("unauthenticated")

