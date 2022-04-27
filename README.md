# Setup
## Installation
`pip install git+https://github.com/Qup42/django-webauthn#egg=django-webauthn`

## `settings.py`
Add `webauthn-django` to installed apps:
```python
INSTALLED_APPS = [
    # other apps
    
    'webauthnauth',
]
```

### WebAuthN Config
Configure the WebAuthN Relying Party
```python
WEBAUTHN_RELYING_PARTY_ID = "localhost"
WEBAUTHN_RELYING_PARTY_NAME = "Test Instance"
WEBAUTHN_EXPECTED_ORIGIN = "http://localhost:8000"
```

## `urls.py`
```python
urlpatterns = [
    path(r'admin/', admin.site.urls),
    path(r'accounts/login/', webauthnauth.views.login_view),
    path(r'accounts/', include('allauth.urls')),
    path(r'webauthnauth/', include('webauthnauth.urls')),
]
```

## First Run
Migrate your database with `./manage.py migrate`

# Usage
Most of the handling as to be done is JS. This module only provides the necessary endpoints and a somewhat general example implementation.

## API
### Registration
1. Django Authenticated Users can retrieve the Config for [`navigator.credentials.create`](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create) at `webauthnauth:register_config`.<br>
**Note: the fields `user.id` and `challenge` in the returned json are base64 encoded.**
2. A Key is registered with [`navigator.credentials.create`](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create) using JavaScript. The resulting [Credential](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create) ([PublicKeyCredential](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential)) instance must be sent to `webauthnauth:register` as JSON.<br>
**Note: `ArrayBuffer` fields such as `rawId`, `response.attestationObject` and `response.clientDataJSON` must be base64 encoded for sending**

The used key is now registered with the logged in user.

### Login
1. Unauthenticated Users can retrieve the Config for [`navigator.credentials.get`](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get) at `webauthnauth:login_config`.<br>
**Note: the fields `challenge` and `allowCredentials[i].id` in the returned json are base64 encoded.**
2. User [`navigator.credentials.get`](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get). The resulting [Credential](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create) ([PublicKeyCredential](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential)) instance must be sent to `webauthnauth:login` as JSON.<br>
**Note: `ArrayBuffer` fields such as `rawId`, `response.attestationObject`, `response.clientDataJSON`, `response.signature` and `response.userHandle` must be base64 encoded for sending**

The user is now logged in. [Django Messages](https://docs.djangoproject.com/en/4.0/ref/contrib/messages/) are set for errors/failures that happen in the login process on the django side.

## Helpers

`WebAuthNLoginForm` is a form that only contains the fields require for WebAuthN Login: Username and a Rember Me field.
`webauthnauth:login` renders the template `account/webauthn/login.html` with the `WebAuthNLoginForm` on get.

The template `webauthn/scripts.html` can be included into templates. It provides two asynchronous functions. The do all the steps required for login/registration that are described above and can be provided with a functions that receives the status ("start", "success", "fail") and an optional message. They are `register(register_status_callback = (status, msg) => {})` and `login_webauthn(username, login_status_callback = (status, msg) => {})`.