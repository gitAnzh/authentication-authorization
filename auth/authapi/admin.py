from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group

from .models import User, Access


class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'usertype', 'is_admin')
    list_filter = ('is_admin',)
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('usertype', 'first_name', 'last_name', 'email')}),
        ('Permissions', {'fields': ('is_admin', 'is_active')}),
    )

    search_fields = ('username', 'usertype')
    filter_horizontal = ()


admin.site.register(Access)
admin.site.register(User, UserAdmin)
admin.site.unregister(Group)
