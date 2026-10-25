"""Enforce the owner's time limit for CVT-677 maintenance-only exceptions."""

import sys
import tomllib
from datetime import date, datetime, timezone
from pathlib import Path

EXPIRES_ON = date(2026, 11, 24)
TEMPORARY_IDS = {"RUSTSEC-2026-0370", "RUSTSEC-2026-0371", "RUSTSEC-2026-0372"}


def expired_ignores(policy, today):
    ignored = {
        entry if isinstance(entry, str) else entry.get("id")
        for entry in policy["advisories"].get("ignore", [])
    }
    return sorted(ignored & TEMPORARY_IDS) if today >= EXPIRES_ON else []


if __name__ == "__main__":
    policy = tomllib.loads((Path(__file__).resolve().parents[1] / "deny.toml").read_text())
    expired = expired_ignores(policy, datetime.now(timezone.utc).date())
    if expired:
        print(f"Expired CVT-677 advisory exceptions ({EXPIRES_ON} UTC): {', '.join(expired)}", file=sys.stderr)
        sys.exit(1)
