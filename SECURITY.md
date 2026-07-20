# Security Policy

## Supported versions

Only the latest released version is supported with security fixes.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository. Do not include pairing PINs, API keys, Wi-Fi credentials, or other secrets in a public issue.

For non-sensitive defects, open a GitHub issue with the bridge version, Tildagon OS version, badge IP range with the final octet removed, and the exact error text.

## Deployment boundary

Hermes Bridge is intended only for trusted private LANs. Do not expose TCP port 8267 to the public internet, port-forward it, or use it across an untrusted VPN. The protocol is authenticated but not encrypted.
