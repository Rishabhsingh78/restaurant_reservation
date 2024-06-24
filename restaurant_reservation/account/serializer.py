from rest_framework import serializers
from .models import User,Slot
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode

class UserSerializer(serializers.ModelSerializer):  # This serializer is for creating the user 
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        extra_Fields = {'password': {'write_only': True}}



    def create(self, validated_data):
        user = User.objects.create_user(username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'])
        
        return user

class UserProfileSerializer(serializers.ModelSerializer):  # this serializer is for getting the user list
    class Meta:
        model = User
        fields = ('id', 'username', 'email')


class LoginSerializer(serializers.Serializer):  # This is for the login 
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self,data):
        username = data.get('username','')
        password = data.get('password','')
        if username and password:
            user = authenticate(username=username, password=password)
            if user is not None:
                if not user.is_active:
                    message = 'User account is disabled.'
                    raise serializers.ValidationError(message)
            else:
                message = 'Unable to log in with provided credentials.'
                raise serializers.ValidationError(message)
            
        else:
            message = 'Must include "username" and "password".'
            raise serializers.ValidationError(message)
        return data                    

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):    # here the value is new_password
        validate_password(value)
        return value

    def validate(self, data):
        user = self.context['request'].user  # here the user is username
        if not user.check_password(data.get('old_password')):
            raise serializers.ValidationError({"old_password": "Wrong password."})
        return data    # here the data is {'old_password': '----', 'new_password': '-------'}

class ForgetPasswordRequestSeriazlier(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email = value).exists():
            return serializers.ValidationError("No user associated with this email address.")
        return value
    

# serializers.py

class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, data):
        try:
            uid = urlsafe_base64_decode(data['uidb64']).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid token")

        if not default_token_generator.check_token(user, data['token']):

            raise serializers.ValidationError("Invalid token")
        print("DATA",data)
        return data

    def save(self, **kwargs):
        uid = urlsafe_base64_decode(self.validated_data['uidb64']).decode()
        print("UID",uid)
        user = User.objects.get(pk=uid)
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user

class SlotSerializer(serializers.ModelSerializer): # this is for the slot booking
    id = serializers.IntegerField(read_only=True)
    class Meta:
        model = Slot
        fields = ['id', 'date', 'start_time', 'end_time', 'location']