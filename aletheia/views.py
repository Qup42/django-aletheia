import logging
import secrets

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.http.response import HttpResponseRedirectBase
from django.urls import reverse_lazy
from django.views.generic.base import TemplateResponseMixin
from django.views.generic.edit import FormMixin, ProcessFormView
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    generate_authentication_options
)
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    RegistrationCredential,
)

from aletheia import settings
from aletheia.forms import WebAuthNLoginForm
from aletheia.models import AuthData
from aletheia.util import base64encode, base64decode, get_request_param, get_redirect_url


class HttpUnprocessableEntity(HttpResponseRedirectBase):
    status_code = 422


logger = logging.getLogger(__name__)

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
    except InvalidRegistrationResponse as e:
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


class LoginView(TemplateResponseMixin, FormMixin, ProcessFormView):
    template_name = "webauthn/login.html"
    form_class = WebAuthNLoginForm
    success_url = reverse_lazy("index")
    redirect_field_name = "next"

    def get_form_kwargs(self):
        kwargs = super(LoginView, self).get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def form_valid(self, form):
        success_url = self.get_success_url()
        return form.login(self.request, redirect_url=success_url)

    def get_success_url(self):
        # Explicitly passed ?next= URL takes precedence
        ret = (
                get_redirect_url(self.request, self.redirect_field_name)
                or self.success_url
        )
        return ret

    def get_context_data(self, **kwargs):
        ret = super(LoginView, self).get_context_data(**kwargs)
        redirect_field_value = get_request_param(self.request, self.redirect_field_name)

        ret.update(
            {
                "redirect_field_name": self.redirect_field_name,
                "redirect_field_value": redirect_field_value,
            }
        )
        return ret


login_view = LoginView.as_view()
