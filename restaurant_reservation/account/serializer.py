from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.password_validation import validate_password

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
