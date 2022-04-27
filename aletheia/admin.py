from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from aletheia.models import AuthData, WebAuthNUser


class WebAuthNUserInline(admin.StackedInline):
    model = WebAuthNUser
    can_delete = False
    verbose_name_plural = 'WebAuthNUser'


class NewUserAdmin(UserAdmin):
    inlines = (WebAuthNUserInline,)


admin.site.register(AuthData)
admin.site.register(WebAuthNUser)
admin.site.unregister(User)
admin.site.register(User, NewUserAdmin)
