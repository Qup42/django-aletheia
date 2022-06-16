from dateutil.relativedelta import relativedelta
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.db import models
from django.utils.timezone import now


def update_last_password_login(sender, request, user, **kwargs):
    if not request.session.get("logging_in_with_webauthn", False):
        user.webauthnuser.last_login_with_password = now()
    request.session["logging_in_with_webauthn"] = False
    user.webauthnuser.save(update_fields=["last_login_with_password"])


def create_webauthnuser(sender, instance, created, **kwargs):
    if created and sender == User:
        WebAuthNUser.objects.create(user=instance)


class AuthData(models.Model):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    name = models.CharField(
        max_length=200, blank=True, help_text="The user-friendly name for this key."
    )
    credential_id = models.CharField(max_length=300, unique=True, help_text="base64 encoded credential_id")
    public_key = models.CharField(max_length=500, help_text="base64 encoded public_key")
    sign_count = models.IntegerField(default=0)
    created_on = models.DateTimeField(auto_now_add=True)
    last_used_on = models.DateTimeField(default=now)

    def __str__(self):
        return f"AuthData(id={self.id}, user={self.user}, name={self.name}, credential_id={self.credential_id}, " \
               f"public_key={self.public_key}, sign_count={self.sign_count}, created_on={self.created_on}, " \
               f"last_used_on={self.last_used_on}) "


class WebAuthNUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    last_login_with_password = models.DateTimeField(default=now)

    @property
    def should_force_password_login(self):
        return self.last_login_with_password + relativedelta(months=6) < now()

    def __str__(self):
        return f"WebAuthNUser(user={self.user}, last_login_with_password={self.last_login_with_password})"
