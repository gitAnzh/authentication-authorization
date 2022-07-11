from django.contrib.auth.models import (BaseUserManager, AbstractBaseUser)
from djongo import models


class UserManager(BaseUserManager):
    def create_user(self, username, usertype, email, password):
        if not username:
            raise ValueError('Users must have an username')

        user = self.create_user(
            email=self.normalize_email(email),
            username=username,
            usertype=usertype,
            password=password,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, usertype, password):
        user = self.create_user(
            username,
            password=password,
            usertype=usertype,
            email=email,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    user_id = models.AutoField(primary_key=True, verbose_name="id")
    email = models.EmailField(max_length=30, unique=True, default=None)
    username = models.CharField(max_length=30, unique=True)
    usertype = models.CharField(max_length=3)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    first_name = models.CharField(max_length=30, default=None)
    last_name = models.CharField(max_length=30, default=None)
    is_marketplace = models.BooleanField(default=False)
    objects = UserManager()

    USERNAME_FIELD = 'username'

    REQUIRED_FIELDS = [
        'usertype',
        'email'
    ]

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, authapi):
        return True

    @property
    def is_staff(self):
        return self.is_admin


class Access(models.Model):
    user = models.OneToOneField("User", on_delete=models.CASCADE)
    access_wms = models.BooleanField(default=False)
    access_supplyf = models.BooleanField(default=False)
    access_catalog = models.BooleanField(default=False)
    access_crm = models.BooleanField(default=False)
    access_rshipment = models.BooleanField(default=False)
    wms_pages = models.CharField(max_length=30, default=None)
    crm_pages = models.CharField(max_length=30, default=None)
    catalog_pages = models.CharField(max_length=30, default=None)
    rshipment_pages = models.CharField(max_length=30, default=None)
    supplyf_pages = models.CharField(max_length=30, default=None)
    USERNAME_FIELD = 'user'

    def __str__(self):
        return self.user.username
