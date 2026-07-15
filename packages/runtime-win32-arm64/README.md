# Palladin client for Windows arm64

This platform package is installed by `@palladin/agent`. Its release artifact contains only the Authenticode-signed native client that activates the fixed AppContainer companion alias from the separately installed Palladin Runtime. It has no lifecycle scripts and is not a standalone JavaScript API.

Installing this npm package does not install, update, or remove the privileged service. If the signed service is unavailable, Hardened mode fails closed.
