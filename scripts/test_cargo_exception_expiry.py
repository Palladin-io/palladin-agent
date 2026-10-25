from datetime import date
import unittest

from check_cargo_exception_expiry import expired_exceptions


class CargoExceptionExpiryTests(unittest.TestCase):
    def test_owner_approved_exceptions_expire_on_the_deadline(self):
        for advisory in ('RUSTSEC-2026-0370', 'RUSTSEC-2026-0371', 'RUSTSEC-2026-0372'):
            policy = {'advisories': {'ignore': [{'id': advisory, 'reason': 'approved'}]}}
            with self.subTest(advisory=advisory):
                self.assertEqual(expired_exceptions(policy, date(2026, 11, 24)), [])
                self.assertEqual(expired_exceptions(policy, date(2026, 11, 25)), [advisory])
                self.assertEqual(expired_exceptions(policy, date(2027, 1, 1)), [advisory])

    def test_removing_the_exceptions_unblocks_later_checks(self):
        policy = {'advisories': {'ignore': [{'id': 'RUSTSEC-2023-0071', 'reason': 'separate review'}]}}
        self.assertEqual(expired_exceptions(policy, date(2027, 1, 1)), [])

    def test_string_form_cannot_bypass_expiry(self):
        policy = {'advisories': {'ignore': ['RUSTSEC-2026-0370']}}
        self.assertEqual(expired_exceptions(policy, date(2026, 11, 25)), ['RUSTSEC-2026-0370'])


if __name__ == '__main__':
    unittest.main()
