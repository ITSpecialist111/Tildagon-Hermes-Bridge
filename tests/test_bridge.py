import json
from pathlib import Path
import sys
import types

import pytest

from deployment import PackageError, decode_package, validate_app_name
from network_policy import is_allowed_address, is_private_address
from pairing import PAIRING_SETTING, generate_pairing_pin, load_pairing_pin
import tools.hermes_badge as hermes_badge


def make_app(tmp_path):
    source = tmp_path / "example"
    source.mkdir()
    for name in ("app.py", "metadata.json", "tildagon.json"):
        (source / name).write_text(name, encoding="ascii")
    return source


def test_same_private_24_policy():
    assert is_allowed_address("192.168.68.60", "192.168.68.31")
    assert is_allowed_address("10.2.3.4", "10.2.3.9")
    assert is_allowed_address("172.20.4.2", "172.20.4.100")
    assert not is_allowed_address("192.168.69.60", "192.168.68.31")
    assert not is_allowed_address("8.8.8.8", "8.8.8.9")
    assert is_private_address("172.31.1.1")
    assert not is_private_address("172.32.1.1")


def test_app_name_validation():
    assert validate_app_name("hermes_app_1") == "hermes_app_1"
    with pytest.raises(PackageError):
        validate_app_name("../escape")
    with pytest.raises(PackageError):
        validate_app_name("bad-name")


def test_pairing_pin_generation_and_persistence(monkeypatch):
    values = {}
    saves = []
    settings_module = types.ModuleType("settings")
    settings_module.get = lambda key, default=None: values.get(key, default)
    settings_module.set = lambda key, value: values.__setitem__(key, value)
    settings_module.save = lambda: saves.append(True)
    monkeypatch.setitem(sys.modules, "settings", settings_module)
    monkeypatch.setattr("pairing.generate_pairing_pin", lambda: "Ab3dE5gH7")

    assert load_pairing_pin() == "Ab3dE5gH7"
    assert values[PAIRING_SETTING] == "Ab3dE5gH7"
    assert saves == [True]
    assert len(generate_pairing_pin(bytes(range(9)))) == 9


def test_package_round_trip_and_hash_check(tmp_path):
    source = make_app(tmp_path)
    name, entries, package = hermes_badge.build_deployment_package(source)
    decoded_name, files = decode_package(package)

    assert name == decoded_name == "example"
    assert len(entries) == len(files) == 3

    payload = json.loads(package)
    payload["files"][0]["sha256"] = "0" * 64
    with pytest.raises(PackageError, match="file hash mismatch"):
        decode_package(json.dumps(payload).encode())


def test_host_accepts_only_literal_private_targets():
    assert hermes_badge.validate_target("192.168.68.31") == "192.168.68.31"
    assert hermes_badge.validate_target("10.0.0.5") == "10.0.0.5"
    with pytest.raises(hermes_badge.BridgeError):
        hermes_badge.validate_target("badge.local")
    with pytest.raises(hermes_badge.BridgeError):
        hermes_badge.validate_target("8.8.8.8")


def test_publication_manifest():
    import tomllib

    root = Path(__file__).parents[1]
    manifest = tomllib.loads((root / "tildagon.toml").read_text(encoding="utf-8"))
    assert manifest["app"] == {
        "name": "Hermes Bridge",
        "category": "Apps",
        "menu": "Apps",
        "wifi_preference": True,
    }
    assert manifest["entry"]["class"] == "HermesBridgeApp"
    assert manifest["metadata"]["author"] == "Graham Hosking"
    assert manifest["metadata"]["version"] == "0.4.0"
    assert manifest["metadata"]["capabilities"][0] == {
        "required": True,
        "feature": {
            "type": "TildagonOSMinimumVersion",
            "version": "2.0.0",
        },
    }
