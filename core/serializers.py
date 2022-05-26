from rest_framework.serializers import ModelSerializer
from .models import User


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True}

        }

    def create(self, validated_data):
        # Validate the password exists and extract it.
        password = validated_data.pop('password', None)

        # Create the user.
        instance = self.Meta.model(**validated_data)

        # If password exists, set it (this automatically hashes it).
        if password is not None:
            instance.set_password(password)

        # Save and return user.
        instance.save()
        return instance
