from .models import User
from .serializer import UserSerializer,LoginSerializer,UserProfileSerializer
from rest_framework import status,generics
from rest_framework.decorators import api_view,permission_classes
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated, IsAdminUser

class UserListView(generics.ListAPIView):  # this the api for the showing the all the user profile in the list form
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAdminUser]


@api_view(['POST'])  # this the for register user or we can say signup api
def create(request):
    if request.method == "POST":
        serializer = UserSerializer(data = request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User registered successfully',},status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])  # this is the api for the login the user
def login(request):
    if request.method == "POST":
        serializer = LoginSerializer(data = request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')

            # Attempt to authenticate user
            user = authenticate(username=username, password=password)

            if user is not None: 
                # Generate or retrieve token for the user
                token, created = Token.objects.get_or_create(user=user)
                return Response({'token': token.key}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])          # this api check the user is logged in or not 
@permission_classes([IsAuthenticated])
def profile(request):
    user = request.user
    print("AKAMAI",user)
    serializer = UserProfileSerializer(user)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        request.user.auth_token.delete()
        return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
    
    except(AttributeError, Token.DoesNotExist):
        return Response({"error": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)
