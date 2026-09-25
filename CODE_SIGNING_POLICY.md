# Code signing policy

Palladin is preparing an application for free open-source Windows code signing. No Windows release is available, and SignPath Foundation has not accepted or signed this project. If accepted, the public attribution will be: **Free code signing provided by SignPath.io, certificate by SignPath Foundation.** Windows will identify SignPath Foundation as the certificate publisher, while the release metadata and source repository identify Palladin as the project.

The signing scope is limited to Windows binaries and installers built from this public repository. The source is [Apache-2.0 licensed](LICENSE). A signing request must originate from a reviewed commit reachable from `main`, use the protected owner-dispatched release workflow and an origin-verified build, and contain only the project's own binaries. Every release requires a separate manual approval by the signing approver; neither an automated request nor a passing CI run grants approval. The signed product name and version must match the release manifest. We verify the final Authenticode signature, timestamp, package identity, artifact hashes, and provenance before staging. A failed check blocks publication; there is no unsigned or test-certificate fallback.

Project roles for this policy:

- **Authors and reviewers:** Palladin repository maintainers with write access; external contributions require maintainer review before merge.
- **Signing approver:** [Patryk Roguszewski](https://github.com/patryk-roguszewski), the project owner.
- **Account security:** every participant in source review or signing must use multifactor authentication on GitHub and SignPath before they can take that role.

The Windows [packaging and installation policy](packaging/windows/README.md) describes the separate system bootstrapper, required administrator consent, managed packages, update checks, and removal behavior. The npm package cannot install a privileged service. The published [Palladin Privacy Policy](https://palladin.io/privacy/) describes the data the service processes; it remains a pre-launch draft and must be finalized before a public release. The CLI connects to a Palladin API endpoint selected by the user and handles approved credentials through the native runtime rather than the Node launcher.

We will add the same Code signing policy link to the Windows download page before offering a signed Windows release. Until the Foundation accepts the application and the Windows release gate passes, there is no Windows download URL or Foundation-signed artifact to verify.
