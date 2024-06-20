from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        extra_Fields = {'password': {'write_only': True}}



    def crate(self, validated_data):
        user = User.objects.create_user(username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'])
        
        return user
    
    


