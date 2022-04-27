from django.apps import AppConfig
from django.contrib.auth.signals import user_logged_in
from django.db.models.signals import post_save


class AppConfig(AppConfig):
    name = 'aletheia'

    def ready(self):
        from .models import update_last_password_login, create_webauthnuser
        user_logged_in.connect(update_last_password_login, dispatch_uid="update_last_password_login")
        post_save.connect(create_webauthnuser, dispatch_uid="create_webauthnuser")
