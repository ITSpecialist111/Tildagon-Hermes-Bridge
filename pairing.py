import os


PAIRING_SETTING = "hermes_bridge_pairing_pin"
PIN_LENGTH = 9
PIN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


def is_valid_pairing_pin(pin):
    return (
        isinstance(pin, str)
        and len(pin) == PIN_LENGTH
        and all(character in PIN_ALPHABET for character in pin)
    )


def generate_pairing_pin(random_bytes=None):
    if random_bytes is None:
        random_bytes = os.urandom(PIN_LENGTH)
    if len(random_bytes) < PIN_LENGTH:
        raise ValueError("not enough random data")
    return "".join(
        PIN_ALPHABET[value % len(PIN_ALPHABET)]
        for value in random_bytes[:PIN_LENGTH]
    )


def _legacy_pairing_pin():
    try:
        from .webrepl_cfg import PASS

        return PASS
    except (ImportError, ValueError):
        return None


def load_pairing_pin():
    import settings

    pin = settings.get(PAIRING_SETTING, None)
    if is_valid_pairing_pin(pin):
        return pin

    legacy_pin = _legacy_pairing_pin()
    pin = legacy_pin if is_valid_pairing_pin(legacy_pin) else generate_pairing_pin()
    try:
        settings.set(PAIRING_SETTING, pin)
        settings.save()
    except Exception:
        pass
    return pin