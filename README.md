# Password Analyzer

A defensive CLI tool that analyzes password strength and checks breach databases
using the Have I Been Pwned k-anonymity API.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![No Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

## Features

- **Secure input**: reads password from `/dev/tty` with echo disabled — never via `argv` or `stdin`
- **Memory hygiene**: `mlock` on secret buffers, `PR_SET_DUMPABLE=0` on Linux, `RLIMIT_CORE=0`
- **HIBP k-anonymity**: only the first 5 chars of the SHA-1 hash leave the machine
- **Pattern detection**: repeats, sequences, keyboard walks
- **Heuristic entropy**: with explicit penalties for weak patterns
- **Retry with backoff**: handles transient API failures
- **Zero dependencies**: pure Python standard library

## Requirements

- Python 3.10 or newer
- Linux, macOS, or Windows
- Internet connection (only for the HIBP breach check)

## Installation

```bash
git clone https://github.com/AbdoMGHt12/password-analyzer.git
cd password-analyzer
python3 password_analyzer.py
```

No `pip install` needed.

## Usage

Interactive (recommended):

```bash
python3 password_analyzer.py
```

Quiet mode (exit code only):

```bash
python3 password_analyzer.py --quiet
```

Disable colors:

```bash
python3 password_analyzer.py --no-color
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Strong |
| 2    | Moderate |
| 3    | Weak |
| 1    | Error |
| 130  | Cancelled |

## Optional: Common Passwords List

To enable the local common-passwords check, download a list and place it as
`common_passwords.txt` next to the script:

```bash
curl -o common_passwords.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
```

## How It Works

1. Reads the password directly from the terminal.
2. Validates length and rejects control characters.
3. Checks against a local common-passwords list (if provided).
4. Computes a heuristic entropy score with pattern penalties.
5. Sends only the first 5 hex chars of the SHA-1 hash to HIBP.
6. Compares the returned suffixes locally.
7. Reports the final rating and exit code.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

### Known Limitations

- CPython immutable `bytes`/`str` cannot be fully wiped from memory.
- `mlock` operates on pages, not individual objects.
- Windows lacks `mlock` and `PR_SET_DUMPABLE` equivalents in stdlib.
- Heuristic entropy is a rough estimate, not a cryptographic measurement.

## License

MIT — see [LICENSE](LICENSE).

## Author

[AbdoMGHt12](https://github.com/AbdoMGHt12)