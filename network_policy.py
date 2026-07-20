def parse_ipv4(address):
    if not isinstance(address, str):
        return None

    parts = address.split(".")
    if len(parts) != 4:
        return None

    try:
        octets = tuple(int(part) for part in parts)
    except ValueError:
        return None

    if any(octet < 0 or octet > 255 for octet in octets):
        return None
    return octets


def is_private_address(address):
    octets = parse_ipv4(address)
    if octets is None:
        return False
    return (
        octets[0] == 10
        or (octets[0] == 172 and 16 <= octets[1] <= 31)
        or octets[:2] == (192, 168)
    )


def is_allowed_address(address, badge_address):
    remote = parse_ipv4(address)
    badge = parse_ipv4(badge_address)
    if remote is None or badge is None or not is_private_address(badge_address):
        return False

    return (
        remote[:3] == badge[:3]
        and 1 <= remote[3] <= 254
        and 1 <= badge[3] <= 254
    )