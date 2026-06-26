# Security Policy

## Supported versions

`dbd-django-oidc-client` is pre-1.0. Security fixes target the most recent
release published on PyPI.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue, pull
request, or discussion for a suspected vulnerability.

- Preferred: use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository (the **Report a vulnerability** button under the **Security**
  tab).
- Alternatively, email **jonny.fuller@dbdriven.solutions** with the details and,
  if possible, a minimal reproduction.

You can expect an acknowledgement within a few business days. Once a fix is
ready we will coordinate a release and, unless you prefer to remain anonymous,
credit you in the advisory.

## Scope

This library is an OpenID Connect relying party, so the highest-impact reports
involve the parts that establish trust:

- ID token validation bypasses (signature, `iss`, `aud`, `azp`, `exp`, or the
  algorithm allowlist).
- PKCE, `state`, or `nonce` handling flaws.
- Authorization code or token leakage.
- Session fixation or cross-tab attacks against the login flow.
