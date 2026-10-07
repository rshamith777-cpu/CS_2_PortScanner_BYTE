# Security Policy

## Responsible Use and Authorization Notice

**PortScope** is designed exclusively for authorized baseline verification, defensive auditing, and educational demonstrations on:
- `localhost` (`127.0.0.1`, `::1`)
- Systems explicitly owned and administered by the operator
- Targets for which explicit, documented permission has been granted

Unauthorized network scanning can be perceived as an adversarial reconnaissance attempt and may violate local, national, and international cybersecurity laws, including but not limited to the Computer Fraud and Abuse Act (CFAA) and equivalent cyber legislation globally.

## Out-of-Scope Capabilities

To ensure strict compliance with defensive engineering standards, this tool deliberately does **not** include:
- SYN stealth scanning (`half-open` / raw packet crafting)
- IDS/IPS firewall evasion techniques
- Packet fragmentation or timing deception
- Credential stuffing or brute forcing
- Banner exploitation or remote code execution payloads
- Mass Internet range scanning or asynchronous subnet sweeps

## Reporting a Vulnerability

If you discover a security vulnerability or bug within the implementation of PortScope:
1. Do **not** open a public issue on GitHub.
2. Please contact the project maintainer via private security advisory or email.
3. Provide reproduction steps, potential impact, and suggested remediations.
4. Maintainers will review the submission, patch any flaws, and acknowledge responsible reporters.
