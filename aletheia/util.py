import base64
from django.utils.http import url_has_allowed_host_and_scheme


def base64encode(s: bytes) -> str:
    return base64.b64encode(s).decode()


def base64decode(s: str) -> bytes:
    return base64.b64decode(s)


def get_request_param(request, param, default=None):
    """
    Gets the parameter param from request. The parameter may be passed as GET or POST parameter.
    """
    if request is None:
        return default
    return request.POST.get(param) or request.GET.get(param, default)


def get_redirect_url(request, redirect_field_name="next"):
    """
    Gets the redirect url for a request. It is passed as GET or POST parameter "next".
    """
    redirect_to = get_request_param(request, redirect_field_name)
    if not url_has_allowed_host_and_scheme(redirect_to, allowed_hosts=None, require_https=True):
        redirect_to = None
    return redirect_to
