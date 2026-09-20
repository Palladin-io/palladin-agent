# Experimental live login discovery (2026-09-18)

Status: local implementation behind a process feature flag; not a production release.

`PALLADIN_EXPERIMENTAL_LIVE_FORMS=1` selects live discovery for the shared native
CLI/MCP Inject service. Unset or `0` keeps verified Form Discovery Maps and the
existing reviewed CLI fallback. Other values fail. An exact tab ID and current
HTTPS URL are required in live mode; `--form-json` is incompatible.

In live mode the runtime does not look up/cache/refresh maps or record candidates.
No map code, data, migration or cache is deleted. The private authenticated
`prepare` message adds optional `liveDetection`; a matching extension returns a
bounded optional `liveForm`. Old extensions fail closed. The runtime rejects
arbitrary fields, persistent selectors, multiple steps and mixed TOTP/login plans.

The extension reuses credential scope/role analysis. It generates one current-step
plan with expiring isolated-world node handles, not CSS locators or page values.
The same native session binds that plan to its tab and document. Exact URL,
visibility, structure, node identity, nonempty controls and form destination are
checked before writing/submitting; handles are consumed after one attempt. A
failed or ambiguous write/submit must not be retried automatically.

One call now runs a bounded sequence of discovered steps (at most eight, sixty
seconds from the first authorized handoff, further limited by the runtime/grant
lease). One credential delivery and one authenticated host connection cover the
sequence. After each confirmed submit, the extension waits for a new current-step
plan on the original exact HTTPS origin and document, then the runtime checks the
plan, field scope and authorization again. Only the current step's fields enter
the extension; the delivered source remains native-only and is dropped when the
operation ends. A TOTP code is generated immediately before its step.

Continuation carries only `ready` with current URL/document/opaque live handles,
or a terminal value-free reason. `no-form` is not authentication evidence. CAPTCHA,
unsupported challenges, missing/ambiguous fields, unchanged steps, cross-origin
navigation and expiry stop the operation; no submitted step is replayed after an
ambiguous response. Password/TOTP cannot be submitted twice. A previously sent
username may accompany a newly discovered password step solely to check that a
populated username still matches; the extension must not rewrite a matching value.

The mechanism is generic: ordinary username-only, combined username/password,
password-only and unsplit authenticator steps can appear through navigation or SPA
replacement. It contains no AWS-specific sequence or URL selectors. Site-specific
exceptions require a failing observed production specimen first. Synthetic tests
prove transitions and security boundaries separately from real-site acceptance.

Authenticated GrantPayload v2 supplies an approved typed TOTP source; native code
selects primary or one unambiguous custom source and generates the code. A v1
frozen code requires refresh. No granted TOTP means no TOTP fill. Neither seed nor
code enters the model. SMS, recovery, passkeys, CAPTCHA and ambiguous forms hand
control back. Split OTP boxes and arbitrary custom widgets remain unsupported.
The actual browser provider is the paired extension; this flag does not enable a
Playwright/CDP credential channel.

## Test and rollback

Use matching rebuilt debug extension and native host from the same worktree.
For a source CLI command set the flag on the process before invoking the signed
macOS development wrapper; for MCP set it in the MCP server environment. Do not
change a profile, API host or default Agent to switch discovery mode.

Rollback: unset the flag or set `0` and restart the CLI/MCP process. This restores
the original map/fallback path without deleting anything. Missing verified maps
will again fail closed. Do not silently fall back to a map after a live write.

Keep maps until live mode has evidence from observed production specimens,
Chromium/native integration, real account login/MFA acceptance and reviewed
security boundaries. Restore map mode for a confirmed live regression while
adding an observed failing specimen. Remove maps only in a separately approved
change after coverage/acceptance demonstrates they add no useful fallback; include
API/cache/candidate consumers and append-only migration policy in that decision.

## Connection recovery — 2026-09-18

Shared CLI/MCP Inject now retries transient socket/transport failure only during
connect and value-free prepare, before opening a credential delivery session.
The total budget is 45 seconds, covering the extension's normal 30-second
reconnect alarm, with 250 ms exponential backoff capped at 2 seconds. Each attempt
uses a new authenticated channel and prepares the same explicit tab/URL again.
Cancellation interrupts both connection and backoff; lifecycle guards remain in
force. Unsafe sockets, invalid frames, failed authentication and semantic target
rejections do not retry. No credential-bearing Inject frame is ever replayed when
its response is lost. Longer extension backoff may exhaust this bounded budget;
the error reports preparation failure and that no credential was sent.

Tests use actual Unix sockets and encrypted handshakes: dropped handshake/prepare,
late host startup, bounded unavailability, cancellation, unsafe socket, invalid or
tampered response, and no replay after losing the Inject response. This addresses
connection recovery without requiring users to reload the extension.

Live diagnosis subsequently confirmed a separate compatibility defect: the running
extension replied to live prepare with the older generic `inject.result/rejected`
shape. The host tried to deserialize this as `prepare.result` and closed the
channel. The host now recognizes only that exact rejection (same protocol, null
transaction ID, live requested) and returns `unsupported-live-detection` bound to
the request nonce. CLI/MCP report that matching updated extension/runtime builds
are required. This semantic rejection is never retried and never requests a grant.
Malformed, cross-operation and success-shaped substitutes remain rejected.
Updating loaded extension code is separate from transient transport recovery.

## Live execution freshness — 2026-09-19

Stored maps remain completely bypassed under the flag. A legacy provider outcome
named `stale-form-map` also represented live DOM failures; CLI/MCP now distinguish
this case as a live-form execution rejection without map lookup or retry.

The live extension adapter re-discovers the current step against the original
bound node identities before every control resolution. Ordinary input-driven
attribute/UI updates no longer invalidate the whole operation, while changed
field roles, constraints, form owner, submit caption/destination, replacement,
visibility and additional fields still reject it. The original expiry is never
extended. Strict registration snapshots are unchanged. Synthetic controlled-input
regressions and encrypted native/Chromium tests pass; real-site acceptance is
recorded separately in the project session notes.

## Native TOTP source integration — 2026-09-19

Live OTP plans use the same native `resolve_login_totp` selection as stored-map
Inject. Authenticated GrantPayload v2 normalizes a protected typed source;
primary TOTP or one unambiguous approved custom TOTP derives a current code.
Only the OTP destination and numeric code enter the provider credential. A v1
saved code fails with refresh-required before forwarding, and multiple custom
sources fail closed. Live discovery still cannot request arbitrary custom IDs.

Regression tests cover the live primary/custom path, ambiguous sources, and
v1 refresh-required. Deploy a compatible consumer before enabling the v2 writer;
existing grants need newly encrypted source material, not merely a field-scope
change. Passing these fixture tests does not establish real-site MFA acceptance.

## Deferred identifier submission — 2026-09-20

Some sites expose a native username control before exposing an enabled native
submit. The private live protocol adds an explicit form version 2 and
`deferred-native-click`, whose opaque selector names the credential scope, not a
guessed button. Supported ordered field shapes are username, password, or username
then password, with their corresponding controls. All handles must be distinct
and belong to the same discovery snapshot. V1 maps and their validator remain
unchanged. An old consumer rejects v2; a new consumer never silently falls back
after filling. TOTP remains on v1; arbitrary DIV clicks, new-password fields and
additional verification data remain unsupported.

The same CLI/MCP call delivers credentials once. It fills the approved controls
once per fresh stage, receives a typed, value-free `submit-ready` containing a fresh pending ID,
URL, document and actual native submit handle, then rechecks cancellation, the
original monotonic deadline, lease and browser lifecycle. It sends a new,
value-free `submit` transaction bound to the original fill transaction, grant,
Entry, exact domain and the complete pending tuple. Only the successful commit
increments the stage counter. The host independently rejects an immediate
`injected` reply to deferred fill, altered bindings, another `submit-ready` after
commit, reused fill transaction IDs and any expired authorization.

Both fill and commit carry a native-derived `expiresAt` epoch-millisecond bound.
The host clamps it to the original monotonic lease before forwarding. The matching
extension must cap pending lifetime at ten seconds using its own monotonic timer,
wait at most five seconds for an enabled native action, observe native disconnect,
and revalidate the exact document, origin, scope, controls, approved identifier
and submit destination synchronously immediately before click. No asynchronous
wait is allowed between final commit validation and click. Timers do not replace
native reauthorization. A queued expired commit must be rejected by the extension.

Failed reauthorization or cancellation before commit sends best-effort,
value-free `cancel-submit`; no acknowledgement is required. Pending state also
expires without a cancel message. Neither secret-bearing fill nor value-free
commit is retried following timeout, transport loss or lost acknowledgement.
After commit handoff, cancellation cannot undo a potentially completed click;
the call waits for the bounded result and never claims remote login success.

`runtime/contracts/inject-provider/live-v2/deferred-submit.json` contains the same
synthetic bytes as the matching extension fixture. Native tests cover envelope
parsing, strict value-free commit, cross-binding rejection and encrypted host
fill/commit exchanges. The runtime/API test verifies one backend credential
request across repeated authorization guards and rejects a second delivery before
another HTTP request. Synthetic deferred transitions do not establish that a
particular production site converts its inactive UI into a native submit control.


### Deferred password continuation and framework settling

A committed identifier stage may continue to a fresh deferred password stage
within the same call and credential delivery. The shared native flow retains the
validated current stage URL; both the CLI service and native host bind the pending
commit to that URL, rather than the initial login URL. Same-origin validation and
submitted-field replay protection still apply, including password replay when a
site returns fresh selector handles.

The extension adapts an already recognized ordinary credential plan into this
same fill/ready/commit executor. After filling, it yields one event-loop task before
preparing the native submit handle, allowing framework input handlers to settle.
This happens before native reauthorization, never between final commit validation
and click. Discovery fixes each control's writable or preserved mode; carried
identities must match the approved username and may not be overwritten.

The additional `live-v2/deferred-password.json` fixture is byte-identical to the
extension's `deferred-password-v2.json`. It covers password-only and carried-identity
wire shapes with synthetic values. Encrypted native-host tests cover a complete
identifier fill/commit followed by password fill/commit in one flow. Public-site
acceptance remains separate from those fixture and protocol assertions.

The ten-second pending-submit lifetime limits when the extension may accept the
commit. After that commit, waiting for the click result and next-page discovery
uses the original native authorization deadline, without renewing it. Expiring
the pending window must not discard a valid result from an already accepted
click. Losing that result still stops the operation without replaying the commit.
