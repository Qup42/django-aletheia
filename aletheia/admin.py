import datetime

from dateutil.relativedelta import relativedelta
from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from django.utils.timezone import now

from aletheia.models import AuthData, WebAuthNUser


class WebAuthNUserInline(admin.StackedInline):
    model = WebAuthNUser
    can_delete = False
    verbose_name_plural = 'WebAuthNUser'


class NewUserAdmin(UserAdmin):
    inlines = (WebAuthNUserInline,)


@admin.register(AuthData)
class AuthDataAdmin(admin.ModelAdmin):
    list_display = ("user", "name", "sign_count", "created_on", "last_used_on")
    list_filter = ("last_used_on", "user__username", "created_on")
    search_fields = ("user__username", "user__first_name", "user__last_name", "name")


class ShouldForcePasswordLoginFilter(admin.SimpleListFilter):
    title = "SHOULD FORCE PASSWORD LOGIN"
    parameter_name = "should_force_password_login"

    def lookups(self, request, model_admin):
        return (
            ('True', True),
            ('False', False)
        )

    def queryset(self, request, queryset):
        if self.value() == "True":
            return queryset.filter(last_login_with_password__lt=now() - relativedelta(months=6))
        elif self.value() == "False":
            return queryset.filter(last_login_with_password__gte=now() - relativedelta(months=6))
        else:
            return queryset


@admin.register(WebAuthNUser)
class WebAuthNUserAdmin(admin.ModelAdmin):
    list_display = ("user", "should_force_password_login", "last_login_with_password")
    list_filter = ("last_login_with_password", ShouldForcePasswordLoginFilter)
    search_fields = ("user__username", "user__first_name", "user__last_name")
    actions = ["force_password_login", "delete_webauthn_keys"]

    @admin.action(description="Force a login with password")
    def force_password_login(self, request, queryset):
        updated = queryset.update(last_login_with_password=datetime.datetime.min)
        self.message_user(request, f"Forcing password login for {updated} users.", messages.SUCCESS)

    @admin.action(description="Delete associated WebAuthN Keys")
    def delete_webauthn_keys(self, request, queryset):
        n, _ = AuthData.objects.filter(user__webauthnuser__in=queryset).delete()
        self.message_user(request, f"Deleted {n} WebAuthN Keys", messages.SUCCESS)


admin.site.unregister(User)
admin.site.register(User, NewUserAdmin)
