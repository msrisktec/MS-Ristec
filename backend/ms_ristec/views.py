from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.core.validators import validate_email
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

@api_view(["POST"])
def signup(request):
    data = request.data
    email = data.get("email")
    password = data.get("password")

    # Validate Email
    try:
        validate_email(email)
    except ValidationError:
        return Response({"detail": "Invalid Email!"}, status=status.HTTP_400_BAD_REQUEST)

    # Check if email is already registered
    if User.objects.filter(email=email).exists():
        return Response({"detail": "Email Already Registered"}, status=status.HTTP_400_BAD_REQUEST)

    # Create user with email as username (or generate a unique username)
    user = User.objects.create_user(username=email, email=email, password=password)
    return Response({"detail": "Profile created"}, status=status.HTTP_200_OK)


@api_view(["POST"])
def login(request):
    data = request.data
    email = data.get("email")
    password = data.get("password")

    try:
        user = User.objects.get(email=email)
    except ObjectDoesNotExist:
        return Response({"detail": "Invalid username/password"}, status=status.HTTP_404_NOT_FOUND)

    # Authenticate user
    user = authenticate(username=user.username, password=password)
    if user is None:
        return Response({"detail": "Invalid username/password"}, status=status.HTTP_404_NOT_FOUND)

    # Generate JWT tokens
    refresh_token = RefreshToken.for_user(user)
    return Response(
        {
            "access_token": str(refresh_token.access_token),
            "refresh_token": str(refresh_token),
        },
        status=status.HTTP_200_OK
    )
