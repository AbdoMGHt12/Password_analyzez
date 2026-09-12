# Security Policy 

## Reporting a Vulnerability

If you discover a security issue, please **do not** open a public issue.

Instead, contact the maintainer directly at:

    opushot76@gmail.com

Include:
- A clear description of the issue
- Steps to reproduce
- Affected versions
- Any proof-of-concept (if applicable)

You can expect an initial response within 7 days.

## Scope

This tool is a **local defensive CLI**. It does not run as a service, does not
listen on any port, and does not store credentials. The main security concerns
are:

- Memory hygiene of the entered password
- Correctness of the k-anonymity logic with HIBP
- Safe handling of network responses

## Out of Scope

- Vulnerabilities in Python itself
- Vulnerabilities in the HIBP API
- Issues requiring physical access to an unlocked machine
- Issues requiring an already-compromised OS or root access

## Supported Versions

Only the latest release on `main` receives security fixes.