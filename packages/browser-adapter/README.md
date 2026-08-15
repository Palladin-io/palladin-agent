# Palladin browser adapter contract

Palladin Inject is an embedded provider operation. The agent opens and owns the
browser, runs Discovery, and calls the adapter with the existing page/session.
Palladin never launches a second browser and never accepts a raw CDP endpoint.

The same flow applies to Playwright, Agent Browser, Claude Browser and Codex Browser:

1. Open the target page in the agent's existing browser session.
2. Dismiss declared cookie/consent overlays and run value-free Discovery.
3. Search Palladin for the requested account and obtain the credential/entry grant.
4. Call the provider adapter with the live page/session object, the form definition, and the
   selected entry. The adapter invokes CLI `inject --provider <provider> --provider-transport-stdio`.
5. Fill and submit through that same page capability. Plaintext never enters model-visible
   tool arguments or logs.

The browser capability stays in the Agent process. An ordinary Playwright WebSocket endpoint cannot
address a context/page created by another Playwright client; CDP would be Chromium-only and would
reintroduce an unauthenticated endpoint. Implementations therefore embed the adapter and pass the
existing `Page` object directly rather than serializing it.

The Playwright package exports this entry point:

```ts
import { injectExistingPlaywrightPage } from '@palladin/playwright-mcp/embedded';
await injectExistingPlaywrightPage(page, { vaultId, entryId, form, reason, wait: '5m' });
```

The adapter receives the page from the agent and returns only a redacted status. It never returns
credential field values. OpenClaw, Claude, Codex, or any other Playwright-based Agent can use this
same entry point; only its small host binding is provider-specific.

## Agent mapping

| Agent | Provider | Adapter ownership |
| --- | --- | --- |
| OpenClaw / Playwright | `playwright` | existing Playwright `Page` |
| Agent Browser | `agent-browser` | existing Agent Browser session |
| Claude Browser | `claude-browser` | current Claude browser tab |
| Codex Browser | `codex-browser` | current Codex browser tab |

Claude and Codex adapters may delegate to their native page APIs, but must preserve the
same authenticated stdio handshake and origin/form validation.
