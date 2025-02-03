from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser


class MyUserManager(BaseUserManager):
    def create_user(self, full_name, date_of_birth, gender, email, mobile, address, password=None, password2=None):
        """
        Creates and saves a User with the given full_name, date_of_birth, gender, email, mobile, address, and password.
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            full_name=full_name,
            date_of_birth=date_of_birth,
            gender=gender,
            email=self.normalize_email(email),
            mobile=mobile,
            address=address,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_staffuser(self, full_name, date_of_birth, gender, email, mobile, address, password=None, password2=None):
        """
        Creates and saves a staff user with the given email, date of
        birth and password.
        """
        user = self.create_user(
            full_name=full_name,
            date_of_birth=date_of_birth,
            gender=gender,
            email=email,
            mobile=mobile,
            address=address,
            password=password,
        )
        user.is_staff = True
        user.save(using=self._db)
        return user


    def create_superuser(self, full_name, date_of_birth, gender, email, mobile, address, password=None):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            full_name=full_name,
            date_of_birth=date_of_birth,
            gender=gender,
            email=email,
            mobile=mobile,
            address=address,
            password=password,
        )
        user.is_admin = True
        user.is_staff = True
        user.save(using=self._db)
        return user


class MyUser(AbstractBaseUser):
    GENDER_CHOICES = [('male', 'male' ), ('female','female'), ('other', 'other')]
    full_name = models.CharField(max_length=20)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    email = models.EmailField(
        verbose_name="email address",
        max_length=50,
        unique=True,
    )
    mobile = models.CharField(max_length=15)
    address = models.CharField(max_length=20)
    password = models.CharField(max_length=20)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    verify_email_otp = models.CharField(max_length=6, blank=True, null=True)
    reset_password_otp = models.CharField(max_length=6, blank=True, null=True)

    objects = MyUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["full_name", "date_of_birth", "gender", "mobile", "address"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Grant all permission to admins?"
        # Simplest possible answer: Yes, always
        return self.is_admin 
    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return self.is_admin 
