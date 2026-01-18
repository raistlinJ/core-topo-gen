#!/usr/bin/env python3
"""End-to-end smoke test for /api/proxmox/validate.

This avoids the UI by:
1) POSTing to /login (form auth, sets Flask session cookie)
2) POSTing to /api/proxmox/validate with that cookie

Default targets nginx TLS proxy at https://localhost.
Use --base-url http://localhost:9090 to hit Flask directly.

Exit codes:
- 0: Proxmox validation succeeded
- 1: Validation failed (auth/network/other)
- 2: Could not log into the web app
"""

from __future__ import annotations

import argparse
import getpass
import json
from typing import Any
from urllib.parse import urlparse

import requests


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke test Proxmox validation via the web API")
    parser.add_argument(
        "--base-url",
        default="https://localhost",
        help="Web base URL (default: https://localhost; use http://localhost:9090 to bypass nginx)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=False,
        help="Disable TLS verification for the base URL (useful for localhost dev certs)",
    )
    parser.add_argument("--admin-username", default="coreadmin", help="Web UI admin username")
    parser.add_argument(
        "--admin-password",
        default=None,
        help="Web UI admin password (omit to prompt)",
    )
    parser.add_argument(
        "--proxmox-url",
        default="https://arlsouth1.utep.edu:8006",
        help="Proxmox API base URL (e.g. https://host:8006)",
    )
    parser.add_argument("--proxmox-username", default="root@pam", help="Proxmox username")
    parser.add_argument(
        "--proxmox-password",
        default=None,
        help="Proxmox password (omit to prompt)",
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        default=True,
        help="Verify Proxmox TLS (default: true)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        default=False,
        help="Disable Proxmox TLS verification (overrides --verify-ssl)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Proxmox validation timeout seconds (default: 10)",
    )
    parser.add_argument(
        "--remember-credentials",
        action="store_true",
        default=False,
        help="Persist proxmox creds after validation (default: false)",
    )
    return parser.parse_args()


def _join_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    path = path if path.startswith("/") else f"/{path}"
    return f"{base}{path}"


def _pretty(obj: Any) -> str:
    try:
        return json.dumps(obj, indent=2, sort_keys=True)
    except Exception:
        return str(obj)


def main() -> int:
    args = _parse_args()

    base_url: str = args.base_url

    parsed_base = urlparse(base_url)
    is_localhost = (parsed_base.hostname or "").lower() in {"localhost", "127.0.0.1"}
    # Default to insecure for localhost https (dev certs). For non-localhost, default to verifying TLS.
    verify_base_tls = True
    if args.insecure or (parsed_base.scheme == "https" and is_localhost):
        verify_base_tls = False

    admin_password = args.admin_password
    if admin_password is None:
        admin_password = getpass.getpass("Web admin password: ")

    proxmox_password = args.proxmox_password
    if proxmox_password is None:
        proxmox_password = getpass.getpass("Proxmox password: ")

    sess = requests.Session()

    if not verify_base_tls:
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    # 1) Login to get session cookie
    login_url = _join_url(base_url, "/login")
    login_resp = sess.post(
        login_url,
        data={"username": args.admin_username, "password": admin_password},
        allow_redirects=True,
        timeout=15,
        verify=verify_base_tls,
    )

    # If auth fails, login page is returned with 401.
    if login_resp.status_code >= 400:
        print(f"login failed: HTTP {login_resp.status_code}")
        print(login_resp.text[:500])
        return 2

    # Probe an authenticated endpoint to ensure we're not being redirected back to /login.
    probe_url = _join_url(base_url, "/api/proxmox/credentials/get")
    probe = sess.post(
        probe_url,
        json={},
        allow_redirects=False,
        timeout=15,
        verify=verify_base_tls,
    )

    if probe.status_code in (301, 302, 303, 307, 308):
        loc = probe.headers.get("Location") or ""
        print(f"login did not stick (redirected to {loc!r})")
        return 2

    if probe.status_code == 403:
        print("logged in, but user is not admin (403)")
        return 2

    # 2) Call validate
    validate_url = _join_url(base_url, "/api/proxmox/validate")
    verify_proxmox_ssl = bool(args.verify_ssl)
    if bool(args.no_verify_ssl):
        verify_proxmox_ssl = False

    payload = {
        "url": args.proxmox_url,
        "username": args.proxmox_username,
        "password": proxmox_password,
        "verify_ssl": verify_proxmox_ssl,
        "timeout": float(args.timeout),
        "remember_credentials": bool(args.remember_credentials),
    }

    resp = sess.post(
        validate_url,
        json=payload,
        timeout=30,
        verify=verify_base_tls,
    )

    print(f"validate: HTTP {resp.status_code}")
    try:
        data = resp.json()
    except Exception:
        print(resp.text)
        return 1

    print(_pretty(data))

    if resp.ok and bool(data.get("success")):
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
