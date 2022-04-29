import logging

from dateutil.relativedelta import relativedelta
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.utils.timezone import now
from webauthn import verify_authentication_response
from webauthn.helpers.exceptions import InvalidAuthenticationResponse
from webauthn.helpers.structs import AuthenticationCredential

from aletheia import settings
from aletheia.models import AuthData
from aletheia.util import base64decode

logger = logging.getLogger(__name__)


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
            messages.error(request, f"Authentication failed", fail_silently=True)
            logger.warning(f"Credential with ID {credential_id} unknown.")
            return None

        if not self.user_can_authenticate(credential.user):
            messages.error(request, f"Authentication failed", fail_silently=True)
            logger.warning(f"User {credential.user.username} is disabled.")
            return None

        try:
            authentication_verification = verify_authentication_response(
                credential=AuthenticationCredential.parse_raw(data),
                expected_challenge=challenge.encode("utf-8"),
                expected_rp_id=settings.RELYING_PARTY_ID,
                expected_origin=settings.EXPECTED_ORIGIN,
                require_user_verification=False,
                credential_current_sign_count=credential.sign_count,
                credential_public_key=base64decode(credential.public_key)
            )
        except InvalidAuthenticationResponse as e:
            messages.error(request, f"Authentication failed", fail_silently=True)
            logger.warning(f"Authentication failed for ID {credential_id}: {e}")
            return None

        if credential.user.webauthnuser.last_login_with_password + relativedelta(months=6) < now():
            messages.error(request, f"Authentication with WebAuthN failed. Please login with password.",
                           fail_silently=True)
            logger.info("Last Password Login > 6 months. Failing login.")
            return None

        credential.sign_count = authentication_verification.new_sign_count
        credential.last_used_on = now()
        credential.save(update_fields=["sign_count", "last_used_on"])
        request.session["logging_in_with_webauthn"] = True
        return credential.user

    def user_can_authenticate(self, user):
        """
        Reject users with is_active=False. Custom user models that don't have
        that attribute are allowed.
        """
        is_active = getattr(user, 'is_active', None)
        return is_active or is_active is None
