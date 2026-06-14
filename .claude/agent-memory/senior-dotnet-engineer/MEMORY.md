# Senior .NET Engineer — Memory Index

- [Agents module users table](agents-users-fk.md) — Agents module has its own `users` table; FK on `enrolled_by`/`deactivated_by` requires the user row to exist there.
- [PresignIconTests pre-existing failure](presign-icon-test-flake.md) — `PresignIconTests.When_CdnNotConfigured...` fails on clean main, unrelated to feature work.
