from django import forms
from django.utils.translation import gettext_lazy as _


class WebAuthNLoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={"autofocus": True, "autocomplete": "username",
                                                             "placeholder": _("Username")}),
                               label=_("Username"))
    client_id = forms.CharField(widget=forms.HiddenInput())
    webauthn_data = forms.CharField(widget=forms.HiddenInput())
    remember = forms.BooleanField(label=_("Remember Me"), required=False)
