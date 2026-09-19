# GrantPayload v2: native TOTP derivation

Status: consumer implementation; producer cutover and release acceptance pending.

CVT-239 requires the native runtime to calculate RFC 6238 at operation time. The
canonical v1 payload instead stores a code computed during grant creation. That
format remains accepted for decoding compatibility but cannot promise a fresh code.
Inject refuses saved v1 primary TOTP with a value-free refresh-required error
before forwarding. Password operations remain compatible.

The additive `palladin.grant-payload.v2` plaintext schema retains existing envelope
cryptography, exact field-set commitments, authorized methods and all scope/key/
revision bindings. Its TOTP fields retain `kind: totp`, `mode: derived`, and contain
exactly `source: totp`, `secret`, `algorithm`, `digits`, `period`. The source is
encrypted to the Agent inside the grant envelope; the backend never decrypts it.
The source requires canonical unpadded uppercase Base32 (2–1024 characters),
SHA1/SHA256/SHA512, 6 or 8 digits and a 15–120 second period. Legacy formats keep
their existing validation. V1 continues rejecting source-shaped values.

After authenticated opening, v2 normalization retains the protected TOTP type.
Existing native TOTP selection returns only code/expiry; full Get redacts sources,
explicit Exec mappings and Script references receive only codes. Sources do not
enter default environment variables. Inject derives a code before provider
forwarding; the extension receives no source descriptor. No new key persistence,
seed logging, or public seed output is introduced.

An OTP destination uses the authenticated primary `credential.totp` if present,
otherwise legacy primary TOTP, otherwise exactly one approved typed custom TOTP.
Multiple custom candidates fail closed. Labels cannot designate the source. The
provider destination remains `credential.totp`; source custom IDs are resolved
inside the native boundary, not chosen by page text.

This main-based change does not introduce experimental live DOM discovery: that
feature currently exists in a separate worktree. Its eventual integration must
reuse this resolver without replacing origin, tab, document or lifecycle checks.

Rollout: ship reviewed consumers before v2 producers; refresh existing grant
material through an authorized Member client. Preserve selected-field scopes.
Do not claim old v1 TOTP snapshots are fresh, and do not silently downgrade v2
sources to v1. Real AWS MFA still requires producer integration, refreshed grant
material and an actual browser acceptance test.
