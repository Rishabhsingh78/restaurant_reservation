from .models import User,Slot,Reservation
from .serializer import UserSerializer,LoginSerializer,UserProfileSerializer,ChangePasswordSerializer,ForgetPasswordRequestSeriazlier,PasswordResetConfirmSerializer,SlotSerializer,ReservationSerializer
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
def reservation_list_create(request):
    if request.method == 'GET':
        slots = Reservation.objects.all()
        serializer = ReservationSerializer(slots,many =True)
        return Response(serializer.data)
    elif request.method == 'POST':
        slot_id = request.data.get('slot_id')
        print("asdfadsfadsfa",slot_id)
        print(f"Received slot_id: {slot_id}") 
        table_number = request.data.get('table_number')
        name = request.data.get('name')
        email = request.data.get('email')
        phone = request.data.get('phone')
        guests = request.data.get('guests')

        # Check if the slot already exists with the given table number
        if Reservation.objects.filter(slot__id=slot_id, slot__table_number=table_number).exists():
            return Response({'error': 'A reservation for this slot and table number already exists.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Ensure the slot exists
        try:
            slot = Slot.objects.get(id=slot_id)
        except Slot.DoesNotExist:
            return Response({'error': 'Slot does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        # Create a new reservation
        reservation = Reservation.objects.create(
            slot=slot,
            name=name,
            email=email,
            phone=phone,
            guests=guests
        )
        serializer = ReservationSerializer(reservation)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(['PUT','DELETE','GET']) # this will be update , delete and see the slots
def reservation_detail(request,pk):
    try:
        slot = Reservation.objects.get(pk = pk)
    except Reservation.DoesNotExist:
        return Response({"message":"User not Exits"},status=status.HTTP_400_BAD_REQUEST)
    
    if request.method == 'GET':
        serializer = ReservationSerializer(slot)
        return Response(serializer.data)
    
    if request.method == 'PUT':
        serializer = ReservationSerializer(slot,data= request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'DELETE':
        slot.delete()
        return Response({"message":"successfully delete"},status=status.HTTP_204_NO_CONTENT)
        
@api_view(['GET','POST']) # this api is for creating and see the slots of all
def slot_list_create(request):
    if request.method == 'GET':
        slots = Slot.objects.all()
        serializer = SlotSerializer(slots,many =True)
        return Response(serializer.data)
    elif request.method == 'POST':
        date = request.data.get('date')
        start_time = request.data.get('start_time')
        end_time = request.data.get('end_time')
        location = request.data.get('location')
        table_number = request.data.get('table_number')

        # Check for duplicate slot
        if Slot.objects.filter(date=date, start_time=start_time, end_time=end_time, location=location, table_number=table_number).exists():
            return Response({'error': 'Slot with these details already exists.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = SlotSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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