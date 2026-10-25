import unittest
from datetime import date

from check_advisory_expiry import expired_ignores


class AdvisoryExpiryTests(unittest.TestCase):
    def test_exceptions_are_valid_only_before_deadline(self):
        for advisory in ("RUSTSEC-2026-0370", "RUSTSEC-2026-0371", "RUSTSEC-2026-0372"):
            for entry in (advisory, {"id": advisory, "reason": "approved"}):
                policy = {"advisories": {"ignore": [entry]}}
                with self.subTest(advisory=advisory, entry=entry):
                    self.assertEqual(expired_ignores(policy, date(2026, 11, 23)), [])
                    self.assertEqual(expired_ignores(policy, date(2026, 11, 24)), [advisory])
                    self.assertEqual(expired_ignores(policy, date(2026, 12, 1)), [advisory])

    def test_removing_temporary_exceptions_unblocks_future_builds(self):
        policy = {"advisories": {"ignore": [{"id": "RUSTSEC-2023-0071"}]}}
        self.assertEqual(expired_ignores(policy, date(2027, 1, 1)), [])
