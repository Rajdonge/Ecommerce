from django.contrib import admin
from .models import MyUser

# Register your models here.
class UserAdmin(admin.ModelAdmin):
    list_display = ['full_name', 'email', 'date_of_birth']
    readonly_fields = ['password']

admin.site.register(MyUser, UserAdmin)  