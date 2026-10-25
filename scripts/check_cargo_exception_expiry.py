from datetime import date, datetime, timezone
from pathlib import Path
import sys
import tomllib


def expired_exceptions(policy, today):
    if today < date(2026, 11, 25):
        return []
    ignored = {
        item if isinstance(item, str) else item.get('id')
        for item in policy.get('advisories', {}).get('ignore', [])
    }
    return sorted(ignored & {'RUSTSEC-2026-0370', 'RUSTSEC-2026-0371', 'RUSTSEC-2026-0372'})


if __name__ == '__main__':
    policy = tomllib.loads((Path(__file__).resolve().parents[1] / 'deny.toml').read_text())
    expired = expired_exceptions(policy, datetime.now(timezone.utc).date())
    if expired:
        sys.exit('Expired Cargo maintenance exceptions must be removed: ' + ', '.join(expired))
