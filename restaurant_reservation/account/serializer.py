from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        extra_Fields = {'password': {'write_only': True}}



    def create(self, validated_data):
        user = User.objects.create_user(username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'])
        
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email')


class LoginSerializer(serializers.Serializer):
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
