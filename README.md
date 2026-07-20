# Hermes Bridge for Tildagon

Hermes Bridge lets a local [Hermes Agent](https://github.com/NousResearch/hermes-agent) build and deploy MicroPython apps to an EMF Camp Tildagon badge over a trusted private LAN.

**Author:** Graham Hosking  
**License:** MIT  
**Tildagon OS:** 2.0.0 or newer

## Install from the Tildagon App Store

Hermes Bridge is listed at
[apps.badge.emfcamp.org/apps/32234323](https://apps.badge.emfcamp.org/apps/32234323/)
with install code **`32234323`**.

1. Connect the badge to Wi-Fi.
2. Open **App Store > Use Code** (called **CodeInstall** on older firmware).
3. Enter `32234323` and install **Hermes Bridge**.

The App Store discovers this public repository through the `tildagon-app` topic. New releases normally appear within 15 minutes.

## Set up the Hermes host

Install the command-line client on the computer running Hermes:

```sh
install -d -m 700 ~/.local/bin ~/.config/hermes-badge
curl -fsSL \
  https://raw.githubusercontent.com/ITSpecialist111/Tildagon-Hermes-Bridge/main/tools/hermes_badge.py \
  -o ~/.local/bin/hermes-badge
chmod 700 ~/.local/bin/hermes-badge
export PATH="$HOME/.local/bin:$PATH"
```

Open **Hermes Bridge** on the badge and press **C**. The screen shows `ARMED`, the badge address, and a pairing PIN. Pair once from the Hermes host:

```sh
export HERMES_BADGE_HOST=192.168.68.31  # use the address shown by the badge
hermes-badge pair
hermes-badge check
```

The PIN prompt does not echo input. It is stored in `~/.config/hermes-badge/password` with mode `600`.

## Deploy an app

A deployable app directory must contain:

- `app.py`
- `metadata.json`
- `tildagon.json`

Deploy it with:

```sh
hermes-badge deploy /path/to/app --name app_folder
```

The badge verifies every SHA-256 digest, writes the complete package to a staging directory, verifies the staged files, atomically replaces the destination app, and resets. The bridge is off again after the reset.

### Natural-language Hermes workflow

You can ask Hermes directly:

```text
Create a Tildagon OS v2 app in /home/hermes/my-badge-app. Include app.py,
metadata.json, and tildagon.json. Validate the Python and JSON, then run:
hermes-badge --host 192.168.68.31 deploy /home/hermes/my-badge-app
--name my_badge_app. Do not alter badge firmware, boot.py, Wi-Fi settings,
or existing apps. Report the on-badge verification result.
```

## Controls

| Button | Action |
| --- | --- |
| C / Confirm | Arm or disarm the bridge |
| F / Cancel | Disarm and exit |

The PIN is visible only while the bridge is armed.

## Security model

- The bridge is off after every reboot and must be manually armed.
- The badge accepts only clients in its own private RFC 1918 `/24`.
- The host client accepts only literal RFC 1918 IPv4 targets.
- Every request requires the per-badge nine-character PIN.
- App names and relative paths are strictly validated.
- Hidden paths, traversal, duplicate files, symbolic links, `.mpy`, and build-cache files are rejected or omitted.
- Packages are limited to 64 files and 192 KiB of decoded content.
- Installation uses staging, SHA-256 verification, atomic replacement, and rollback.
- A successful deployment resets the badge and closes TCP port `8267`.
- USB IN remains available for recovery.

The protocol uses plain HTTP because the badge is resource constrained. Use it only on a trusted, WPA-protected private LAN. Do not port-forward TCP `8267` or expose it through an untrusted VPN.

## Direct USB development install

These commands install only the app directory and do not flash or erase the badge:

```powershell
mpremote fs mkdir :/apps
mpremote fs mkdir :/apps/hermes_bridge
mpremote fs cp app.py :/apps/hermes_bridge/app.py
mpremote fs cp deployment.py :/apps/hermes_bridge/deployment.py
mpremote fs cp network_policy.py :/apps/hermes_bridge/network_policy.py
mpremote fs cp pairing.py :/apps/hermes_bridge/pairing.py
mpremote fs cp dev/metadata.json :/apps/hermes_bridge/metadata.json
mpremote fs cp dev/tildagon.json :/apps/hermes_bridge/tildagon.json
mpremote reset
```

## Development

```sh
python -m pip install pytest
python -m pytest -q
python -m py_compile app.py deployment.py network_policy.py pairing.py tools/hermes_badge.py
```

The App Store release archive contains only the badge runtime, `tildagon.toml`, and the license. Documentation, tests, development manifests, and host tools are excluded with `.gitattributes`.

## Limits

Hermes Bridge is a development tool, not a general remote shell. It deploys complete app packages under `/apps`; it does not expose firmware flashing, `boot.py`, badge settings, or arbitrary filesystem commands.
