import binascii
import hashlib
import json
import os
import shutil


PROTOCOL_VERSION = 1
MAX_PACKAGE_BYTES = 196608
MAX_FILE_COUNT = 64
MAX_PATH_BYTES = 96
REQUIRED_FILES = {"app.py", "metadata.json", "tildagon.json"}


class PackageError(ValueError):
    pass


def sha256_hex(data):
    return binascii.hexlify(hashlib.sha256(data).digest()).decode()


def validate_app_name(name):
    if not isinstance(name, str) or not 1 <= len(name) <= 48:
        raise PackageError("invalid app name")
    if any(
        not (
            "a" <= character <= "z"
            or "A" <= character <= "Z"
            or "0" <= character <= "9"
            or character == "_"
        )
        for character in name
    ):
        raise PackageError("invalid app name")
    return name


def validate_relative_path(path):
    if not isinstance(path, str) or not path or "\\" in path:
        raise PackageError("invalid file path")
    if len(path.encode("utf-8")) > MAX_PATH_BYTES:
        raise PackageError("file path too long")

    parts = path.split("/")
    if any(
        not part
        or part in (".", "..")
        or part.startswith(".")
        or any(ord(character) < 32 or ord(character) == 127 for character in part)
        for part in parts
    ):
        raise PackageError("invalid file path")
    return path


def decode_package(body):
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception as error:
        raise PackageError("invalid JSON package") from error

    if not isinstance(payload, dict) or payload.get("protocol") != PROTOCOL_VERSION:
        raise PackageError("unsupported deployment protocol")

    app_name = validate_app_name(payload.get("app"))
    entries = payload.get("files")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_FILE_COUNT:
        raise PackageError("invalid file list")

    decoded = []
    seen = set()
    total_size = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise PackageError("invalid file entry")
        path = validate_relative_path(entry.get("path"))
        if path in seen:
            raise PackageError("duplicate file path")

        content = entry.get("content")
        expected_hash = entry.get("sha256")
        if not isinstance(content, str) or not isinstance(expected_hash, str):
            raise PackageError("invalid file entry")
        try:
            data = binascii.a2b_base64(content.encode("ascii"))
        except Exception as error:
            raise PackageError("invalid file encoding") from error
        if sha256_hex(data) != expected_hash.lower():
            raise PackageError("file hash mismatch")

        total_size += len(data)
        if total_size > MAX_PACKAGE_BYTES:
            raise PackageError("deployment package too large")
        seen.add(path)
        decoded.append((path, data))

    if not REQUIRED_FILES.issubset(seen):
        raise PackageError("deployment is missing required files")
    return app_name, decoded


def _exists(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False


def _ensure_directory(path):
    current = ""
    for part in path.strip("/").split("/"):
        current += "/" + part
        try:
            os.mkdir(current)
        except OSError:
            pass


def _remove_tree(path):
    if not _exists(path):
        return
    try:
        shutil.rmtree(path)
    except Exception:
        pass


def install_package(app_name, files, apps_dir="/apps", work_dir="/data"):
    app_name = validate_app_name(app_name)
    _ensure_directory(apps_dir)
    _ensure_directory(work_dir)

    target = apps_dir.rstrip("/") + "/" + app_name
    stage = work_dir.rstrip("/") + "/hermes_stage_" + app_name
    backup = work_dir.rstrip("/") + "/hermes_backup_" + app_name
    _remove_tree(stage)
    _remove_tree(backup)
    _ensure_directory(stage)

    try:
        for relative_path, data in files:
            validate_relative_path(relative_path)
            destination = stage + "/" + relative_path
            parent = destination.rsplit("/", 1)[0]
            _ensure_directory(parent)
            with open(destination, "wb") as file_handle:
                file_handle.write(data)
            with open(destination, "rb") as file_handle:
                if sha256_hex(file_handle.read()) != sha256_hex(data):
                    raise PackageError("staged file verification failed")

        had_target = _exists(target)
        if had_target:
            os.rename(target, backup)
        try:
            os.rename(stage, target)
        except Exception:
            if had_target and _exists(backup) and not _exists(target):
                os.rename(backup, target)
            raise
        _remove_tree(backup)
        return len(files)
    except Exception:
        _remove_tree(stage)
        raise