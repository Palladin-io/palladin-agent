# Browser handoff contract

The host adapter must return one controlled external-browser tab whose stable identifier is the
positive WebExtensions tab ID used by the Palladin extension. Immediately before Inject it must
read the exact current HTTPS URL from that same tab.

The adapter must fail closed when it cannot prove that relationship. An active-tab query, page
title, URL-only search, CDP target ID, Playwright session ID, or a handle from another browser
profile is not an equivalent target.
