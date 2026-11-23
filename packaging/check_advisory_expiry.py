"""Enforce the owner's time limits for temporary advisory exceptions."""

import sys
import tomllib
from datetime import date, datetime, timezone
from pathlib import Path

EXPIRES_ON = date(2026, 11, 24)
TEMPORARY_IDS = {"RUSTSEC-2026-0370", "RUSTSEC-2026-0371", "RUSTSEC-2026-0372"}
MCP_EXPIRES_ON = date(2026, 11, 25)
MCP_TEMPORARY_IDS = {"RUSTSEC-2026-0457", "RUSTSEC-2026-0462", "RUSTSEC-2026-0543"}


def expired_ignores(policy, today):
    ignored = {
        entry if isinstance(entry, str) else entry.get("id")
        for entry in policy["advisories"].get("ignore", [])
    }
    expired = ignored & TEMPORARY_IDS if today >= EXPIRES_ON else set()
    if today >= MCP_EXPIRES_ON:
        expired |= ignored & MCP_TEMPORARY_IDS
    return sorted(expired)


if __name__ == "__main__":
    policy = tomllib.loads((Path(__file__).resolve().parents[1] / "deny.toml").read_text())
    expired = expired_ignores(policy, datetime.now(timezone.utc).date())
    if expired:
        print(f"Expired advisory exceptions: {', '.join(expired)}", file=sys.stderr)
        sys.exit(1)
