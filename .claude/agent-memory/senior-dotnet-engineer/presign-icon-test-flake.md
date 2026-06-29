---
name: presign-icon-test-flake
description: PresignIconTests CDN-not-configured test fails on clean main, not caused by feature branches
metadata:
  type: project
---

`Palladin.Tests.Integrations.Features.Vault.PresignIconTests.When_CdnNotConfigured_PresignsVaultIcon_Then_Returns503` fails even in complete isolation on a clean `main` checkout — expects 503 but gets 200.

**Why:** the test depends on CDN-not-configured state that is not properly isolated in the shared `ApiFactory` fixture (likely CDN config bleeds in from another test or the fixture default).

**How to apply:** If a full `dotnet test` run shows only this one Vault test failing while your changes are in another module, do not treat it as a regression you introduced. Note it in the PR as a pre-existing issue. Verify by running it isolated against `origin/main` if unsure.
