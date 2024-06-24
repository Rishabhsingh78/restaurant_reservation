from .models import User,Slot
from .serializer import UserSerializer,LoginSerializer,UserProfileSerializer,ChangePasswordSerializer,ForgetPasswordRequestSeriazlier,PasswordResetConfirmSerializer,SlotSerializer
from rest_framework import status,generics
from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def changePassword(request):
    user = request.user
    serializer = ChangePasswordSerializer(data = request.data,context={'request': request})

    if serializer.is_valid():
        if not user.check_password(serializer.data.get('old_password')):
            return Response({'old_password': ["Wrong Password"]}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(serializer.data.get('new_password'))
        user.save()
        update_session_auth_hash(request, user)
        return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def request_Password(request):
    serializer = ForgetPasswordRequestSeriazlier(data = request.data)

    if serializer.is_valid():
        email = serializer.validated_data['email']
        user = User.objects.get(email = email)

        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        password_reset_url = request.build_absolute_uri(reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token}))

        send_mail(
            'Password Reset Request',
            f'Click the link below to reset your password:\n{password_reset_url}',
            'from@example.com',
            [user.email],
            fail_silently=False,
        )

        return Response({'message':'Password link sent to the user email'},status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def password_reset_confirm(request, uidb64, token):
    serializer = PasswordResetConfirmSerializer(data = request.data)
    serializer.context['uidb64'] = uidb64
    serializer.context['token'] = token
    if serializer.is_valid():
        serializer.save()
        return Response({'message':'Password has reset Successfully'},status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET','POST']) # this api is for creating and see the slots of all
def slot_list_create(request):
    if request.method == 'GET':
        slots = Slot.objects.all()
        serializer = SlotSerializer(slots,many =True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = SlotSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
            "message": "Slot created successfully",
            "slot": serializer.data
        }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['PUT','DELETE','GET']) # this will be update , delete and see the slots
def slot_detail(request,pk):
    try:
        slot = Slot.objects.get(pk = pk)
    except Slot.DoesNotExist:
        return Response({"message":"User not Exits"},status=status.HTTP_400_BAD_REQUEST)
    
    if request.method == 'GET':
        serializer = SlotSerializer(slot)
        return Response(serializer.data)
    
    if request.method == 'PUT':
        serializer = SlotSerializer(slot,data= request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'DELETE':
        slot.delete()
        return Response({"message":"successfully delete"},status=status.HTTP_204_NO_CONTENT)