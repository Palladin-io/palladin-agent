---
name: agents-users-fk
description: Agents module has its own users table with FK constraints; seed users there before setting agent enrolled_by/deactivated_by
metadata:
  type: project
---

The Agents module keeps a local `users` table (entity `Palladin.Module.Agents.Domain.User`), populated cross-module via the `OnUserUpserted` trigger. The `agents` table has FK constraints `fk_agents_enrolled_by` and `fk_agents_deactivated_by` pointing at it.

**Why:** modules communicate only through integration events; each module owns the slice of user data it needs. The Identity-module `User` returned by `SeedUserAsync` is NOT the same row as the Agents-module `User`.

**How to apply:** In integration tests, when an endpoint writes `EnrolledBy`/`DeactivatedBy` (e.g. approve/deactivate agent) or when seeding an agent with those fields set, first call `apiFactory.Services.SeedAgentsUserAsync(userId)` so the FK target exists. Otherwise `SaveChangesAsync` throws `PostgresException 23503`. The `Reactivate` flow does not touch these FK columns, so it needs no extra seeding.
