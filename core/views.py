import datetime
import string
import random

from django.core.mail import send_mail
from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework.views import APIView

from .authentication import create_access_token, JWTAuthentication, create_refresh_token, decode_refresh_token
from .models import User, UserToken, Reset
from .serializers import UserSerializer


class RegisterAPIView(APIView):

    def post(self, request):
        data = request.data

        # Validate password and confirm password are the same.
        if data['password'] != data['password_confirm']:
            raise exceptions.APIException('Passwords do not match')

        # Validate data. If it does not contain all the fields
        # defined in the serializer, raise exception.
        serializer = UserSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        # Save serializer and return the contained data.
        serializer.save()
        return Response(serializer.data)


class LoginAPIView(APIView):

    def post(self, request):
        # Extraxt email and password.
        email = request.data['email']
        password = request.data['password']

        # User is the email
        user = User.objects.filter(email=email).first()

        # Check if email exists.
        if user is None or not user.check_password(password):
            raise exceptions.AuthenticationFailed('Invalid credentials')

        # Check if password is correct.
        if not user.check_password(password):
            raise exceptions.AuthenticationFailed('Invalid credentials')

        # Create access and refresh tokens here
        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)

        # Create User token to indicate that the user has logged in with
        # a specific refresh token associated.
        UserToken.objects.create(
            user_id=user.id,
            token=refresh_token,
            expired_at=datetime.datetime.utcnow() + datetime.timedelta(days=7)
        )

        response = Response()
        # Add refresh_token to cookies.
        response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)

        # Add access_token to data
        response.data = {
            'token': access_token
        }

        return response


class UserAPIView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        return Response(UserSerializer(request.user).data)


class RefreshAPIView(APIView):
    def post(self, request):
        # Get refresh_token from cookies
        refresh_token = request.COOKIES.get('refresh_token')

        # Decode refresh_token
        id = decode_refresh_token(refresh_token)

        # Check if the refresh token is in the database
        # (the user has not logout).
        if not UserToken.objects.filter(
                user_id=id,
                token=refresh_token,
                expired_at__gt=datetime.datetime.now(tz=datetime.timezone.utc)
        ).exists():
            raise exceptions.AuthenticationFailed("unauthenticated")

        # Create a new access token
        access_token = create_access_token(id)

        return Response({
            'token': access_token
        })


class LogoutAPIView(APIView):

    def post(self, request):
        # Get refresh_token from cookies
        refresh_token = request.COOKIES.get('refresh_token')

        # Find user token and delete it, so the refresh token
        # is not valid anymore.
        UserToken.objects.filter(token=refresh_token).delete()

        response = Response()
        response.delete_cookie(key='refresh_token')
        response.data = {
            'message': 'success'
        }
        return response


class ForgotAPIView(APIView):
    def post(self, request):
        email = request.data['email']
        token = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

        Reset.objects.create(
            email=request.data['email'],
            token=token
        )

        url ='http://localhost:8080/reset/' + token

        send_mail(
            subject='Reset your password!',
            message='Click <a href="%s">here</a> to reset your password' % url,
            from_email='from@example.com',
            recipient_list=[email]
        )

        return Response({
            'message': 'success'
        })


class ResetAPIView(APIView):
    def post(self, request):
        data = request.data

        # Validate new password and confirm password are the same.
        if data['password'] != data['password_confirm']:
            raise exceptions.APIException('Passwords do not match')

        reset_password = Reset.objects.filter(token=data['token']).first()

        if not reset_password:
            raise exceptions.APIException('Invalid link!')

        user = User.objects.filter(email=reset_password.email).first()

        if not user:
            raise exceptions.APIException('User not found!')

        user.set_password(data['password'])
        user.save()

        return Response({
            'message': 'success'
        })