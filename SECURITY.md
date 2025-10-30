# Security Policy

Aunsorm aims to be a best-in-class secure communication suite. Responsible
reporting allows us to protect users quickly and transparently.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.5.x   | ✅         |
| < 0.1   | ❌         |

We currently support the latest patch release on the 0.1.x line. Older releases
will only receive security fixes on a best-effort basis.

## Reporting a Vulnerability

1. Email a detailed report to [security@aunsorm.dev](mailto:security@aunsorm.dev).
   Include proof-of-concept steps, impact analysis, and any mitigation ideas.
2. If the vulnerability involves highly sensitive data or cross-tenant impact,
   encrypt your message using the PGP key published in `docs/SECURITY-KEY.asc`.
   (Until that key is published, request a temporary key in your initial email.)
3. Do **not** open a public GitHub issue until we have coordinated a disclosure
   timeline together.

We will acknowledge new reports within **3 business days**. Within **10 business
 days** we will share our initial assessment, target fix version, and—if
 applicable—request additional information.

## Disclosure Process

- We strive to release a patched version within **30 days** of confirming a
  vulnerability. Complex issues may require more time; we will keep reporters
  informed of delays.
- Once a fix is available, we will publish security advisories, update
  `CHANGELOG.md`, and notify known integrators.
- Credit will be given to reporters who wish to be acknowledged. Anonymous
  reports are always respected.

## Safe Harbor

We do not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, or
  service disruption.
- Report vulnerabilities promptly and allow us reasonable time to remediate
  before public disclosure.
- Follow the steps outlined above and comply with applicable laws.

Thank you for helping keep Aunsorm users safe.
