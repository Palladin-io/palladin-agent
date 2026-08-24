# Generic browser handoff

This is the source-tree fallback used before a host-specific adapter is packaged. A target adapter
must return one controlled external-browser tab whose stable identifier is the positive
WebExtensions tab ID used by the selected runtime provider. Immediately before Inject it must read
the exact current HTTPS URL from that same tab.

The adapter must fail closed when it cannot prove that relationship. An active-tab query, page
title, URL-only search, CDP target ID, Playwright session ID, or a handle from another browser
profile is not an equivalent target.
