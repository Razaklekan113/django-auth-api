from xml.dom import ValidationErr
from django.forms import ValidationError
from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util


class UserRegistrationSerializer(serializers.ModelSerializer):
    # we are writing this because we need to confirm our registration request
    confirm_password = serializers.CharField(style={"input_type": "password"}, write_only=True)
    class Meta:
        model = User
        fields = ["email", "name", "password", "confirm_password", "tc"]
        confirm_password = serializers.CharField(style={"input_type": "password"}, write_only=True)
        extra_kwargs = {
            "password" : {"write_only": True}
        }

    # Validating password and confirming password while Registration

    def validate(self, attrs):
        password = attrs.get("password")
        confirm_password = attrs.get("confirm_password")
        if password != confirm_password:
            raise serializers.ValidationError("Password and confirm Password dosen't match")
        return attrs


    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ["email","password"]

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "name"]

class UserChangePasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(max_length=255, style = {"input_type": "password"}, write_only=True)
    confirm_password= serializers.CharField(max_length=255, style = {"input_type": "password"}, write_only=True)
    class Meta:
        fields = ["new_password", "confirm_passwordd"]

    def validate(self, attrs):
        new_password = attrs.get("new_password")
        confirm_password = attrs.get("confirm_password")
        user = self.context.get("user")
        if new_password != confirm_password:
            raise serializers.ValidationError("Password and confirm Password dosen't match")
        user.set_password(new_password)
        user.save()
        return attrs

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ["email"]

    def validate(self, attrs):
        email = attrs.get('email').lower()
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print("Encoded UID", uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("Password reset token", token)
            link = "https://localhost:3000/api/user/reset/"+uid+"/"+token
            print("Password reset link", link)
            # Send EMail
            body = "Click The Following Link to Reset Your Password " + link
            data = {
                "subject":"Reset Your Password",
                "body": body,
                "to_email":user.email,
            }
            Util.send_email(data)
            return attrs
        else:
            raise ValidationErr("You are not a Registered User")

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style = {"input_type": "password"}, write_only=True)
    confirm_password = serializers.CharField(max_length=255, style = {"input_type": "password"}, write_only=True)
    class Meta:
        fields = ["password", "confirm_password"]

    def validate(self, attrs):
        try:
            password = attrs.get("password")
            confirm_password = attrs.get("confirm_password")
            uid = self.context.get("uid")
            token = self.context.get("token")
            if password != confirm_password:
                raise serializers.ValidationError("Password and confirm Password dosen't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError("Token is not valid or expired")
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError("Token is not valid or expired")