import datetime

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from webauthnauth.models import WebAuthNUser


class Command(BaseCommand):
    help = "Prepares already existing users for the use with WebAuthN."

    def handle(self, *args, **options):
        for user in User.objects.filter(webauthnuser__isnull=True).all():
            WebAuthNUser.objects.create(user=user, last_login_with_password=datetime.datetime.min)
