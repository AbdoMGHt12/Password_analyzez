#!/usr/bin/env python3
import argparse
import atexit
import binascii
import ctypes
import ctypes.util
import gc
import hashlib
import hmac
import math
import os
import random
import re
import signal
import socket
import ssl
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

HIBP_API = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "PasswordAnalyzer/5.0"
REQUEST_TIMEOUT = 8
MAX_PASSWORD_LENGTH = 1024
MAX_RESPONSE_BYTES = 5_000_000
EXPECTED_CONTENT_TYPE = "text/plain"
ALLOWED_HOST = "api.pwnedpasswords.com"
ALLOWED_SCHEME = "https"
ALLOWED_PORT = 443
MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0
RETRY_MAX_DELAY = 8.0
COMMON_WORDS_FILE = "common_passwords.txt"


class Colors:
    def __init__(self, enabled: bool) -> None:
        if enabled:
            self.GREEN = "\033[92m"
            self.YELLOW = "\033[93m"
            self.RED = "\033[91m"
            self.CYAN = "\033[96m"
            self.BOLD = "\033[1m"
            self.END = "\033[0m"
        else:
            self.GREEN = self.YELLOW = self.RED = ""
            self.CYAN = self.BOLD = self.END = ""


class SecretVault:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buffers = []
        self._mlocked = {}
        self._libc = None
        self._init_libc()

    def _init_libc(self) -> None:
        if os.name == "nt":
            return
        try:
            name = ctypes.util.find_library("c") or "libc.so.6"
            self._libc = ctypes.CDLL(name, use_errno=True)
        except Exception:
            self._libc = None

    def register(self, buf: bytearray) -> None:
        with self._lock:
            self._buffers.append(buf)
            self._try_mlock(buf)

    def _try_mlock(self, buf: bytearray) -> None:
        if self._libc is None or not hasattr(self._libc, "mlock"):
            return
        size = len(buf)
        if size == 0:
            return
        try:
            arr = (ctypes.c_char * size).from_buffer(buf)
            addr = ctypes.addressof(arr)
            rc = self._libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
            if rc == 0:
                self._mlocked[id(buf)] = (addr, size)
        except Exception:
            pass

    def wipe(self, buf: bytearray) -> None:
        with self._lock:
            try:
                for i in range(len(buf)):
                    buf[i] = 0
            except Exception:
                pass
            key = id(buf)
            entry = self._mlocked.pop(key, None)
            if entry is not None and self._libc is not None:
                addr, size = entry
                if hasattr(self._libc, "munlock"):
                    try:
                        self._libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
                    except Exception:
                        pass
            try:
                self._buffers.remove(buf)
            except ValueError:
                pass

    def wipe_all(self) -> None:
        with self._lock:
            for buf in list(self._buffers):
                try:
                    for i in range(len(buf)):
                        buf[i] = 0
                except Exception:
                    pass
            if self._libc is not None and hasattr(self._libc, "munlock"):
                for addr, size in self._mlocked.values():
                    try:
                        self._libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
                    except Exception:
                        pass
            self._mlocked.clear()
            self._buffers.clear()


def harden_process() -> None:
    try:
        os.umask(0o077)
    except Exception:
        pass

    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass

    if sys.platform.startswith("linux"):
        try:
            name = ctypes.util.find_library("c") or "libc.so.6"
            libc = ctypes.CDLL(name, use_errno=True)
            if hasattr(libc, "prctl"):
                PR_SET_DUMPABLE = 4
                libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        except Exception:
            pass


def secure_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.options |= ssl.OP_NO_COMPRESSION
    except AttributeError:
        pass
    try:
        ctx.options |= ssl.OP_NO_RENEGOTIATION
    except AttributeError:
        pass
    try:
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")
    except ssl.SSLError:
        pass
    return ctx


def validate_password(pwd_buf) -> None:
    if not isinstance(pwd_buf, (bytes, bytearray, memoryview)):
        raise ValueError("Password must be a bytes-like object.")
    if len(pwd_buf) == 0:
        raise ValueError("Password is empty.")
    if len(pwd_buf) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password exceeds {MAX_PASSWORD_LENGTH} bytes.")
    if b"\x00" in pwd_buf:
        raise ValueError("Password contains a NUL byte.")
    for b in pwd_buf:
        if b < 0x20 and b != 0x09:
            raise ValueError("Password contains control characters.")


def validate_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != ALLOWED_SCHEME:
        raise ValueError("Invalid URL scheme.")
    if parsed.hostname != ALLOWED_HOST:
        raise ValueError("Invalid host.")
    port = parsed.port or ALLOWED_PORT
    if port != ALLOWED_PORT:
        raise ValueError("Invalid port.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URL are not allowed.")
    if parsed.query or parsed.fragment:
        raise ValueError("Query or fragment in URL is not allowed.")


def constant_time_eq_buf(a, b) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for i in range(len(a)):
        diff |= a[i] ^ b[i]
    return diff == 0


def load_common_passwords(path: str) -> list:
    entries = []
    if not path or not os.path.isfile(path):
        return entries
    try:
        with open(path, "rb") as f:
            for line in f:
                line = line.rstrip(b"\r\n")
                if not line or line.startswith(b"#"):
                    continue
                if len(line) > MAX_PASSWORD_LENGTH:
                    continue
                entries.append(line)
                if len(entries) >= 1_000_000:
                    break
    except OSError:
        return []
    entries.sort(key=len)
    return entries


def is_common_password(pwd_buf, common_list) -> bool:
    length = len(pwd_buf)
    for entry in common_list:
        if len(entry) != length:
            continue
        if constant_time_eq_buf(pwd_buf, entry):
            return True
    return False


def _count_classes(pwd_buf) -> int:
    classes = 0
    if re.search(rb"[a-z]", pwd_buf):
        classes += 1
    if re.search(rb"[A-Z]", pwd_buf):
        classes += 1
    if re.search(rb"\d", pwd_buf):
        classes += 1
    if re.search(rb"[^a-zA-Z0-9]", pwd_buf):
        classes += 1
    return classes


def _has_sequence(pwd_buf, min_len: int = 4) -> bool:
    if len(pwd_buf) < min_len:
        return False
    run = 1
    direction = 0
    for i in range(1, len(pwd_buf)):
        d = pwd_buf[i] - pwd_buf[i - 1]
        if d in (1, -1):
            if direction == 0 or direction == d:
                direction = d
                run += 1
                if run >= min_len:
                    return True
            else:
                direction = d
                run = 2
        else:
            direction = 0
            run = 1
    return False


def _has_repeat(pwd_buf, min_len: int = 3) -> bool:
    if len(pwd_buf) < min_len:
        return False
    run = 1
    for i in range(1, len(pwd_buf)):
        if pwd_buf[i] == pwd_buf[i - 1]:
            run += 1
            if run >= min_len:
                return True
        else:
            run = 1
    return False


def _has_keyboard_pattern(pwd_buf, min_len: int = 4) -> bool:
    rows = (
        b"qwertyuiop",
        b"asdfghjkl",
        b"zxcvbnm",
        b"1234567890",
        b"qazwsxedc",
    )
    if len(pwd_buf) < min_len:
        return False
    lower = bytearray(len(pwd_buf))
    for i, b in enumerate(pwd_buf):
        lower[i] = b + 0x20 if 0x41 <= b <= 0x5A else b
    try:
        for row in rows:
            for start in range(len(row) - min_len + 1):
                chunk = row[start:start + min_len]
                if chunk in lower:
                    return True
                if chunk[::-1] in lower:
                    return True
    finally:
        for i in range(len(lower)):
            lower[i] = 0
    return False


def estimate_entropy(pwd_buf, common_list) -> tuple:
    length = len(pwd_buf)
    if length == 0:
        return 0.0, []

    penalties = []

    pool = 0
    if re.search(rb"[a-z]", pwd_buf):
        pool += 26
    if re.search(rb"[A-Z]", pwd_buf):
        pool += 26
    if re.search(rb"\d", pwd_buf):
        pool += 10
    if re.search(rb"[^a-zA-Z0-9]", pwd_buf):
        pool += 33

    if pool == 0:
        raw = 0.0
    else:
        raw = length * math.log2(pool)

    effective = raw

    if _has_repeat(pwd_buf):
        effective *= 0.55
        penalties.append("repeated characters reduce entropy")

    if _has_sequence(pwd_buf):
        effective *= 0.60
        penalties.append("sequential characters reduce entropy")

    if _has_keyboard_pattern(pwd_buf):
        effective *= 0.50
        penalties.append("keyboard walk pattern detected")

    if common_list and is_common_password(pwd_buf, common_list):
        effective *= 0.10
        penalties.append("matches a known common password")

    if length < 8:
        effective *= 0.60
        penalties.append("short length severely limits entropy")

    if effective < 0:
        effective = 0.0

    return effective, penalties


def _sha1_prefix_suffix(pwd_buf) -> tuple:
    h = hashlib.sha1()
    h.update(memoryview(pwd_buf))
    digest = h.digest()
    hex_bytes = binascii.hexlify(digest).upper()
    prefix = hex_bytes[:5]
    suffix = hex_bytes[5:]
    del digest
    del hex_bytes
    return prefix, suffix


def _single_hibp_request(url: str, suffix: bytes, prefix_used: str) -> int:
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Add-Padding": "true",
        "Accept": EXPECTED_CONTENT_TYPE,
        "Accept-Encoding": "identity",
        "Connection": "close",
    })
    ctx = secure_ssl_context()
    chunks = []
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx) as resp:
            if resp.status != 200:
                return -1
            ctype = resp.headers.get("Content-Type", "")
            if ctype.split(";")[0].strip().lower() != EXPECTED_CONTENT_TYPE:
                return -1
            cl = resp.headers.get("Content-Length")
            if cl is not None and cl.isdigit() and int(cl) > MAX_RESPONSE_BYTES:
                return -1
            total = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    return -1
                chunks.append(chunk)
    except (urllib.error.URLError, urllib.error.HTTPError,
            ssl.SSLError, socket.timeout, TimeoutError, OSError, ValueError):
        return -1

    raw = b"".join(chunks)
    del chunks

    try:
        data = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return -1
    finally:
        raw = b""

    try:
        for line in data.splitlines():
            if ":" not in line:
                continue
            h, count = line.split(":", 1)
            h = h.strip()
            if len(h) != len(suffix):
                continue
            try:
                h_bytes = h.encode("ascii")
            except UnicodeEncodeError:
                continue
            if hmac.compare_digest(h_bytes, suffix):
                try:
                    return int(count.strip())
                except ValueError:
                    return 0
        return 0
    finally:
        del data


def check_pwned(pwd_buf) -> int:
    prefix, suffix = _sha1_prefix_suffix(pwd_buf)
    prefix_str = prefix.decode("ascii")
    url = HIBP_API + prefix_str
    try:
        validate_url(url)
    except ValueError:
        return -1

    last_error = -1
    for attempt in range(MAX_RETRIES):
        result = _single_hibp_request(url, suffix, prefix_str)
        if result != -1:
            return result
        last_error = result
        if attempt < MAX_RETRIES - 1:
            delay = min(RETRY_MAX_DELAY, RETRY_BASE_DELAY * (2 ** attempt))
            delay += random.uniform(0, 0.5)
            time.sleep(delay)

    return last_error


def read_password(prompt: str, vault: SecretVault) -> bytearray:
    if os.name == "nt":
        return _read_password_windows(prompt, vault)
    return _read_password_unix(prompt, vault)


def _read_password_windows(prompt: str, vault: SecretVault) -> bytearray:
    import msvcrt
    sys.stderr.write(prompt)
    sys.stderr.flush()
    buf = bytearray()
    try:
        while len(buf) < MAX_PASSWORD_LENGTH:
            ch = msvcrt.getch()
            if ch in (b"\r", b"\n"):
                break
            if ch == b"\x03":
                raise KeyboardInterrupt
            if ch in (b"\x08", b"\x7f"):
                if buf:
                    buf.pop()
                continue
            if ch in (b"\x00", b"\xe0"):
                msvcrt.getch()
                continue
            buf.extend(ch)
    finally:
        sys.stderr.write("\n")
        sys.stderr.flush()
    vault.register(buf)
    return buf


def _read_password_unix(prompt: str, vault: SecretVault) -> bytearray:
    import termios
    flags = os.O_RDWR
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open("/dev/tty", flags)
    except OSError as e:
        raise RuntimeError(f"Cannot open /dev/tty securely: {e}")

    buf = bytearray()
    try:
        try:
            os.write(fd, prompt.encode("utf-8", "replace"))
        except OSError:
            pass
        try:
            old = termios.tcgetattr(fd)
        except termios.error:
            raise RuntimeError("Terminal does not support required attributes.")
        new = termios.tcgetattr(fd)
        new[3] &= ~termios.ECHO
        new[3] &= ~termios.ECHONL
        new[6][termios.VMIN] = 1
        new[6][termios.VTIME] = 0
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, new)
            while len(buf) < MAX_PASSWORD_LENGTH:
                ch = os.read(fd, 1)
                if not ch:
                    break
                if ch in (b"\n", b"\r"):
                    break
                if ch == b"\x03":
                    raise KeyboardInterrupt
                if ch in (b"\x7f", b"\x08"):
                    if buf:
                        buf.pop()
                    continue
                buf.extend(ch)
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            except Exception:
                pass
            try:
                os.write(fd, b"\n")
            except OSError:
                pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    vault.register(buf)
    return buf


def analyze_password(pwd_buf: bytearray, vault: SecretVault, colors: Colors,
                     quiet: bool, common_list: list) -> int:
    try:
        validate_password(pwd_buf)
    except ValueError as e:
        if not quiet:
            print(f"{colors.RED}Error: {e}{colors.END}")
        return 1

    score = 0
    feedback = []

    length = len(pwd_buf)
    if length >= 16:
        score += 3
        feedback.append(f"{colors.GREEN}[+] Excellent length{colors.END}")
    elif length >= 12:
        score += 2
        feedback.append(f"{colors.GREEN}[+] Good length{colors.END}")
    elif length >= 8:
        score += 1
        feedback.append(f"{colors.YELLOW}[!] Acceptable length{colors.END}")
    else:
        feedback.append(f"{colors.RED}[-] Too short{colors.END}")

    for pattern, msg in (
        (rb"[a-z]", "No lowercase letters"),
        (rb"[A-Z]", "No uppercase letters"),
        (rb"\d", "No digits"),
        (rb"[^a-zA-Z0-9]", "No symbols"),
    ):
        if re.search(pattern, pwd_buf):
            score += 1
        else:
            feedback.append(f"{colors.RED}[-] {msg}{colors.END}")

    if common_list and is_common_password(pwd_buf, common_list):
        feedback.append(f"{colors.RED}[-] Found in local common-passwords list{colors.END}")
        score = 0

    entropy, penalties = estimate_entropy(pwd_buf, common_list)
    if not quiet:
        print(f"{colors.CYAN}Estimated entropy:{colors.END} {entropy:.1f} bits (heuristic)")
        for p in penalties:
            print(f"  {colors.YELLOW}[!] {p}{colors.END}")
        print(f"{colors.CYAN}Checking breach databases...{colors.END}")

    pwned = check_pwned(pwd_buf)
    if pwned > 0:
        feedback.append(f"{colors.RED}[-] Found in {pwned:,} known breaches. Change it immediately.{colors.END}")
    elif pwned == 0:
        feedback.append(f"{colors.GREEN}[+] Not found in known breaches{colors.END}")
    else:
        feedback.append(f"{colors.YELLOW}[!] Could not verify breaches{colors.END}")

    if score >= 7 and pwned == 0 and entropy >= 60:
        rating = f"{colors.GREEN}{colors.BOLD}Very Strong{colors.END}"
        exit_code = 0
    elif score >= 5 and pwned <= 0 and entropy >= 35:
        rating = f"{colors.YELLOW}{colors.BOLD}Moderate{colors.END}"
        exit_code = 2
    else:
        rating = f"{colors.RED}{colors.BOLD}Weak{colors.END}"
        exit_code = 3

    if not quiet:
        print(f"\n{colors.BOLD}Result:{colors.END} {rating} (Score: {score}/8)\n")
        for line in feedback:
            print(f"  {line}")
        print()

    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password_analyzer.py",
        description="Analyze password strength and check for known breaches.",
    )
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress all output (only exit code is meaningful).")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output.")
    parser.add_argument("--common-file", default=COMMON_WORDS_FILE,
                        help="Path to a newline-separated common-passwords file.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    harden_process()

    color_enabled = (
        not args.no_color
        and "NO_COLOR" not in os.environ
        and hasattr(sys.stdout, "isatty")
        and sys.stdout.isatty()
    )
    colors = Colors(enabled=color_enabled)

    common_list = load_common_passwords(args.common_file)

    vault = SecretVault()
    atexit.register(vault.wipe_all)

    def _handler(signum, _frame):
        vault.wipe_all()
        sys.exit(128 + signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError, AttributeError):
            pass
    if hasattr(signal, "SIGHUP"):
        try:
            signal.signal(signal.SIGHUP, _handler)
        except (ValueError, OSError, AttributeError):
            pass

    if not args.quiet:
        sys.stderr.write(
            f"\n{colors.BOLD}{colors.CYAN}=== Password Analyzer v5.0 ==={colors.END}\n"
        )
        if common_list:
            sys.stderr.write(
                f"{colors.CYAN}Loaded {len(common_list):,} common passwords "
                f"from {args.common_file}{colors.END}\n\n"
            )
        else:
            sys.stderr.write(
                f"{colors.YELLOW}No local common-passwords file loaded "
                f"(expected: {args.common_file}).{colors.END}\n\n"
            )
        sys.stderr.flush()

    prompt = "Enter password (hidden): " if not args.quiet else ""
    try:
        pwd_buf = read_password(prompt, vault)
    except KeyboardInterrupt:
        if not args.quiet:
            sys.stderr.write("\nCancelled.\n")
        return 130
    except RuntimeError as e:
        if not args.quiet:
            sys.stderr.write(f"{colors.RED}Error: {e}{colors.END}\n")
        return 1
    except Exception as e:
        if not args.quiet:
            sys.stderr.write(f"{colors.RED}Error reading password: {e}{colors.END}\n")
        return 1

    exit_code = 1
    try:
        if len(pwd_buf) == 0:
            if not args.quiet:
                sys.stderr.write(f"{colors.RED}No password provided.{colors.END}\n")
            return 1
        exit_code = analyze_password(pwd_buf, vault, colors, args.quiet, common_list)
    finally:
        vault.wipe(pwd_buf)
        pwd_buf = None
        vault.wipe_all()
        try:
            gc.collect()
        except Exception:
            pass
    return exit_code


if __name__ == "__main__":
    sys.exit(main())