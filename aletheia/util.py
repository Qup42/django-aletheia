import base64


def base64encode(s: bytes) -> str:
    return base64.b64encode(s).decode()


def base64decode(s: str) -> bytes:
    return base64.b64decode(s)

