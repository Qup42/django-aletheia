from dateutil.relativedelta import relativedelta
from django.conf import settings

RELYING_PARTY_ID = getattr(
    settings, "WEBAUTHN_RELYING_PARTY_ID", "localhost"
)

RELYING_PARTY_NAME = getattr(
    settings, "WEBAUTHN_RELYING_PARTY_NAME", "Test Relying Party"
)

EXPECTED_ORIGIN = getattr(
    settings, "WEBAUTHN_EXPECTED_ORIGIN", "http://localhost:8000"
)

FORCE_PASSWORD_TIMEOUT = getattr(
    settings, "WEBAUTHN_FORCE_PASSWORD_TIMEOUT", relativedelta(months=6)
)
