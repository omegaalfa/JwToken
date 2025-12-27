# Security Policy

This project prioritizes rapid remediation of vulnerabilities related to JWT tokens, cryptographic keys, and authentication flows. Below are the support details and recommended process for reporting security issues.

## Supported Versions

Security updates are actively maintained for:

| Version | Active Support |
| --- | --- |
| `main` (main branch) | ✅ |
| `1.x` (releases compatible with PHP 8.4+) | ✅ |
| previous versions | ❌ (no updates) |

If you're using an older release, consider upgrading to benefit from security fixes and cryptographic improvements.

## Reporting a Vulnerability

1. Create a private security issue on GitHub using the security advisory template if available.
2. Alternatively, send an email to security@omegaalfa.dev with:
   - Complete description of the scenario and impact (forged token, invalid signature, etc.).
   - Minimal steps to reproduce, including `php`/`openssl` commands when applicable.
   - PHP version (8.4+) and the `JwToken` branch or tag in use.
3. If possible, include a PoC (e.g., PHP script + token) to expedite triage.

## What to Expect

- 📩 We confirm receipt within 24 business hours.
- 🛡️ We request additional information as needed and keep you updated every 2–3 days during investigation.
- 📦 We publish fixes as quickly as possible and notify via the issue or email used for initial contact.
- If there's no feedback within 7 days, we'll review priority and communicate current status.

## Best Practices for Reporters

- Do not share details publicly until a fix or official advisory is available.
- Include urgency level or severity classification (e.g., high if unlimited tokens can be forged).
- Indicate whether the vulnerability affects HMAC and RS256 integrations, especially key rotation routines.

Thank you for helping keep JwToken secure. Together we protect critical authentication flows.# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

Use this section to tell people how to report a vulnerability.

Tell them where to go, how often they can expect to get an update on a
reported vulnerability, what to expect if the vulnerability is accepted or
declined, etc.
