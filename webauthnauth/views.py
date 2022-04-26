import base64
import json
import secrets
from json import JSONDecodeError

from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.http.response import HttpResponseRedirectBase
from django.views import View
from django.views.generic.base import TemplateResponseMixin
from django.views.generic.edit import FormMixin
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes, generate_authentication_options
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    RegistrationCredential,
)

from webauthnauth import settings
from webauthnauth.forms import WebAuthNLoginForm
from webauthnauth.models import AuthData


class HttpUnprocessableEntity(HttpResponseRedirectBase):
    status_code = 422


@login_required
def registration_config(request):
    challenge = secrets.token_urlsafe(64)

    request.session["challenge"] = challenge

    currently_registered = AuthData.objects.filter(user=request.user).all()

    options = generate_registration_options(
        rp_id=settings.RELYING_PARTY_ID,
        rp_name=settings.RELYING_PARTY_NAME,
        user_id=str(request.user.id),
        user_name=f"{request.user.first_name} {request.user.last_name}",
        user_display_name=request.user.username,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            #            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64decode(auth_data.credential_id)) for auth_data in
                             currently_registered],
        challenge=challenge.encode("utf-8"),
        timeout=300000,
    )
    return HttpResponse(content=options_to_json(options), content_type="application/json")


def base64encode(s: bytes) -> str:
    return base64.b64encode(s).decode()


def base64decode(s: str) -> bytes:
    return base64.b64decode(s)


@login_required()
def register(request):
    if "challenge" not in request.session:
        messages.error(request, "Missing challenge in this session.", fail_silently=True)
        return HttpUnprocessableEntity(f"Missing challenge in this session.")
    else:
        challenge = request.session.get("challenge")

    registration_response = request.body
    try:
        registered_key = verify_registration_response(
            credential=RegistrationCredential.parse_raw(registration_response.decode("utf-8")),
            expected_challenge=challenge.encode("utf-8"),
            expected_origin=settings.EXPECTED_ORIGIN,
            expected_rp_id=settings.RELYING_PARTY_ID,
            require_user_verification=False,
        )
    except Exception as e:
        messages.error(request, f"Registration failed. Error: {e}", fail_silently=True)
        return HttpUnprocessableEntity(f"Registration failed. Error: {e}")

    AuthData.objects.create(
        user=request.user,
        credential_id=base64encode(registered_key.credential_id),
        public_key=base64encode(registered_key.credential_public_key),
    )

    messages.success(request, "WebAuthN Client registered.", fail_silently=True)
    return HttpResponse("Success")


def login_config(request):
    challenge = secrets.token_urlsafe(64)

    request.session["challenge"] = challenge

    if "login" not in request.POST:
        messages.error(request, f"Missing \"login\" POST field", fail_silently=True)
        return HttpUnprocessableEntity(f"Missing \"login\" POST field")
    else:
        username = request.POST["login"]

    users_keys = AuthData.objects.filter(user__username=username).all()

    options = generate_authentication_options(
        rp_id=settings.RELYING_PARTY_ID,
        challenge=challenge.encode("utf-8"),
        timeout=120000,
        user_verification=UserVerificationRequirement.DISCOURAGED,
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64decode(auth_data.credential_id))
                           for auth_data in users_keys],
    )

    return HttpResponse(content=options_to_json(options), content_type="application/json")


class LoginView(View, FormMixin, TemplateResponseMixin):
    template_name = "account/webauthn/login.html"
    form_class = WebAuthNLoginForm

    def get(self, request, *args, **kwargs):
        """Handle GET requests: instantiate a blank version of the form."""
        return self.render_to_response(self.get_context_data())

    def post(self, request, *args, **kwargs):
        try:
            login_response_json = json.loads(request.body.decode("utf-8"))
        except JSONDecodeError as error:
            message = f"Login failed. Failed parsing JSON. Error: {error}"
            messages.error(request, message, fail_silently=True)
            return HttpUnprocessableEntity(message)

        user = authenticate(request,
                            # TODO: this dict access might fail
                            credential_id=base64encode(base64url_to_bytes(login_response_json["id"])),
                            data=request.body.decode("utf-8"))
        if user is None:
            return HttpResponseForbidden(f"Login failed.")

        login(request, user)

        return HttpResponse("Success")


login_view = LoginView.as_view()
