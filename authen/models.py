from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, username, password, **extra_fields)



class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, verbose_name="E-mail")
    username = models.CharField(max_length=30, null=True, blank=True, unique=True, verbose_name="Логин")
    first_name = models.CharField(max_length=255, null=True, blank=True, verbose_name="Имя")
    last_name = models.CharField(max_length=255, null=True, blank=True, verbose_name="Фамилия")
    middle_name = models.CharField(max_length=255, null=True, blank=True, verbose_name="Отчества")
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: '+9989999999'. Up to 15 digits allowed.")
    phone = models.CharField(validators=[phone_regex], max_length=250, null=True, blank=True, verbose_name="Телефон", unique=True)
    avatar = models.ImageField(upload_to="avatar/", null=True, blank=True, verbose_name="Изображение")
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    counrty = models.CharField(max_length=250, null=True, blank=True, verbose_name="Страна, город")
    name_university = models.CharField(max_length=250, null=True, blank=True, verbose_name="Название ВУЗа")
    speciality = models.CharField(max_length=250, null=True, blank=True, verbose_name="Специальность")
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    def __str__(self):
        return self.email

    class Meta:
        db_table = "table_user"
        verbose_name = "Пользователи"
        verbose_name_plural = "Пользователи"