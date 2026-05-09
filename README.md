# FinalSecurityandSecureCoding
i couldnt push my final to the other repository

# Secret Scanner CLI Tool

## Overview

This project is a Python-based command-line interface (CLI) application designed to detect hardcoded secrets within files or directories. The scanner searches for common secret patterns using regular expressions and reports findings that may expose sensitive information.

The tool helps developers identify accidentally committed credentials before deployment or version control submission.

---

## Features

- Scan a single file or entire directory
- Recursive directory scanning
- Regex-based secret detection
- Logging support
- Detailed findings report
- Lightweight and easy to run
- Uses only Python standard library modules

---

## Detection Logic

The application uses regular expressions (regex) to identify patterns commonly associated with sensitive credentials.

### Included Secret Patterns

| Secret Type | Description |
|---|---|
| AWS Access Key | Detects AWS access keys beginning with `AKIA` |
| Google API Key | Detects Google API credentials beginning with `AIza` |
| Generic Password | Detects password assignments such as `password=` |
| JWT Token | Detects JSON Web Tokens |
| GitHub Token | Detects GitHub personal access tokens |
| Private Key | Detects RSA/OpenSSH private key blocks |
| Slack Token | Detects Slack authentication tokens |
| Stripe API Key | Detects Stripe live secret keys |

## Requirements

- Python 3.8+

No third-party libraries are required.

---
