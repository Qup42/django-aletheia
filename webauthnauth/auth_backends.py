from dateutil.relativedelta import relativedelta
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.utils import timezone
from webauthn import verify_authentication_response
from webauthn.helpers.structs import AuthenticationCredential

from webauthnauth import settings
from webauthnauth.models import AuthData
from webauthnauth.views import base64decode


class WebAuthNBackend:

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def authenticate(self, request, credential_id: str, data: str = None):
        """
        Checks whether the request has correctly provided a WebAuthN Attestation to log in.
        This among others includes checking the challenge and checking the signature.

        The convention in Django is to return a user if authenticate succeeded.
        If authenticate fails None is returned.
        """
        challenge = request.session.get("challenge")
        if not challenge:
            messages.error(request, f"Missing challenge in session", fail_silently=True)
            return None

        credential = AuthData.objects.filter(credential_id=credential_id).first()
        if not credential:
            messages.error(request, f"This credential_id is not registered.", fail_silently=True)
            return None

        if credential.user.webauthnuser.last_login_with_password + relativedelta(months=6) < timezone.now():
            messages.error(request, f"Authentication with WebAuthN failed. Please login with password.",
                           fail_silently=True)
            return None

        try:
            authentication_verification = verify_authentication_response(
                credential=AuthenticationCredential.parse_raw(data),
                expected_challenge=challenge.encode("utf-8"),
                expected_rp_id=settings.RELYING_PARTY_ID,
                expected_origin=settings.EXPECTED_ORIGIN,
                require_user_verification=False,
                credential_current_sign_count=0,
                credential_public_key=base64decode(credential.public_key)
            )
        except Exception as e:
            # TODO: be more specific and catch more specific errors
            messages.error(request, f"Authentication failed", fail_silently=True)
            return None

        request.session["logging_in_with_webauthn"] = True
        return credential.user
