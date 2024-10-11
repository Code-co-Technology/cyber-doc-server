from django.core.exceptions import ValidationError
from django.core.validators import MaxLengthValidator

from django.contrib.auth.models import Group
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework.exceptions import AuthenticationFailed

from authen.models import CustomUser


class IncorrectCredentialsError(serializers.ValidationError):
    pass


class UnverifiedAccountError(serializers.ValidationError):
    pass


class UserGroupSerizliers(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ["id", "name"]


class UserSignUpSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(max_length=50, validators=[
            MaxLengthValidator(limit_value=50, message="Имя не может превышать 50 символов.")],)
    username = serializers.CharField(max_length=255, read_only=True) 
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)
    email = serializers.EmailField(validators=[UniqueValidator(queryset=CustomUser.objects.all())])
    groups = serializers.PrimaryKeyRelatedField(queryset=Group.objects.all(), many=True, required=False)

    class Meta:
        model = CustomUser
        fields = ["id", "username", "first_name", "email", "phone", "password", "confirm_password", "groups"]
        extra_kwargs = {"first_name": {"required": True}, "last_name": {"required": True}}

    def validate_password(self, value):

        try:
            validate_password(value)
        except ValidationError as exc:
            raise serializers.ValidationError(str(exc))

        return value

    def create(self, validated_data):

        if validated_data["password"] != validated_data["confirm_password"]:
            raise serializers.ValidationError({"error": "Эти пароли не совпадают."})

        validated_data.pop("confirm_password")
        groups_data = validated_data.pop('groups', [])
        email = validated_data.get("email")
        username = email.split("@")[0] 
        create = get_user_model().objects.create_user(username=username, **validated_data)
        create.groups.set(groups_data)

        return create


class UserSigInSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=50, min_length=2)
    password = serializers.CharField(max_length=50, min_length=1)

    class Meta:
        model = get_user_model()
        fields = ["email", "password"]
        read_only_fields = ("email",)

    def validate(self, data):
        if self.context.get("request") and self.context["request"].method == "POST":
            allowed_keys = set(self.fields.keys())
            input_keys = set(data.keys())
            extra_keys = input_keys - allowed_keys

            if extra_keys:
                raise serializers.ValidationError(f"Дополнительные ключи не допускаются.: {', '.join(extra_keys)}")

        return data


class UserInformationSerializer(serializers.ModelSerializer):
    groups = UserGroupSerizliers(many=True, read_only=True)

    class Meta:
        model = CustomUser
        fields = ["id", "email", "first_name", "last_name", "middle_name", "phone", "avatar", "counrty", "name_university", "speciality", "groups"]


class UserUpdateSerializer(serializers.ModelSerializer):
    email = serializers.CharField(required=True, max_length=30, validators=[UniqueValidator(queryset=CustomUser.objects.all()),
            MaxLengthValidator(limit_value=20, message="Длина адреса электронной почты не может превышать 30 символов.")],)
    avatar = serializers.ImageField(max_length=None, use_url=True)
    avatar = serializers.ImageField(max_length=None, allow_empty_file=False, allow_null=False, use_url=False, required=False,)
    phone = serializers.CharField(required=True, max_length=15, validators=[UniqueValidator(queryset=CustomUser.objects.all()),
            MaxLengthValidator(limit_value=20, message="Длина Телефон не может превышать 15 символов.")],)

    class Meta:
        model = CustomUser
        fields = ["id", "email", "first_name", "last_name", "middle_name", "phone", "avatar", "counrty", "name_university", "speciality"]

    def update(self, instance, validated_data):
        instance.email = validated_data.get("email", instance.email)
        instance.first_name = validated_data.get("first_name", instance.first_name)
        instance.last_name = validated_data.get("last_name", instance.last_name)
        instance.middle_name = validated_data.get("middle_name", instance.middle_name)
        instance.phone = validated_data.get("phone", instance.phone)
        instance.counrty = validated_data.get("counrty", instance.counrty)
        instance.name_university = validated_data.get("name_university", instance.name_university)
        instance.speciality = validated_data.get("speciality", instance.speciality)

        if instance.avatar == None:
            instance.avatar = self.context.get("avatar")
        else:
            instance.avatar = validated_data.get("avatar", instance.avatar)
        instance.save()

        return instance


class ChangePasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        """
        Проверьте, совпадает ли new_password с confirmed_password.
        """
        if data.get("new_password") != data.get("confirm_password"):
            raise serializers.ValidationError("Новый пароль и подтверждение пароля должны совпадать.")

        return data


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ["email"]


class PasswordResetCompleteSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, max_length=32, write_only=True)
    confirm_password = serializers.CharField(min_length=8, max_length=32, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ["password", "confirm_password", "token", "uidb64"]

    def validate(self, attrs):
        password = attrs.get("password")
        confirm_password = attrs.get("confirm_password")
        token = attrs.get("token")
        uidb64 = attrs.get("uidb64")

        if password != confirm_password:
            raise serializers.ValidationError({"error": "Пароли не совпадают"})

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("Неверная ссылка", 401)

            user.set_password(password)
            user.save()
            return user
        except Exception:
            raise AuthenticationFailed("Неверная ссылка", 401)

