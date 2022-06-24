from django import forms
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.http import HttpResponseRedirect
from django.utils.translation import gettext_lazy as _
from webauthn import base64url_to_bytes

from aletheia import settings
from aletheia.util import base64encode


class WebAuthNLoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={"autofocus": True, "autocomplete": "username",
                                                             "placeholder": _("Username")}),
                               label=_("Username"))
    client_id = forms.CharField(widget=forms.HiddenInput())
    webauthn_data = forms.CharField(widget=forms.HiddenInput())
    remember = forms.BooleanField(label=_("Remember Me"), required=False)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request", None)
        super(WebAuthNLoginForm, self).__init__(*args, **kwargs)

    def clean(self):
        super(WebAuthNLoginForm, self).clean()
        if self._errors:
            return

        credential_id = self.cleaned_data["client_id"]
        webauthn_data = self.cleaned_data["webauthn_data"]

        user = authenticate(self.request,
                            credential_id=base64encode(base64url_to_bytes(credential_id)),
                            data=webauthn_data)

        if user:
            self.user = user
        else:
            raise forms.ValidationError("Login Failed")

        return self.cleaned_data

    def login(self, request, redirect_url=None):
        login(request, self.user)
        messages.success(request, f"Successfully signed in as {self.user.username}.", fail_silently=True)

        remember = settings.SESSION_REMEMBER
        if remember is None:
            remember = self.cleaned_data["remember"]
        if remember:
            # None means global expiry setting -> SESSION_COOKIE_AGE
            request.session.set_expiry(None)
        else:
            request.session.set_expiry(0)

        response = HttpResponseRedirect(redirect_url)
        response.set_cookie("django-aletheia-webauthn-user", self.user.username, secure=True)

        return response
