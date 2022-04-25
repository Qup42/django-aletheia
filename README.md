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
TODO