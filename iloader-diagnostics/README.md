# Unofficial iloader D2 network diagnostics

This is an unofficial diagnostic adaptation of iloader 2.4.0, not an official
release and not endorsed by its author. Upstream: https://iloader.app and
https://github.com/nab138/iloader. Preserve the upstream MIT license and branding
notice when distributing it.

The sole functional changes are bounded, fixed-vocabulary network-error
summaries in the existing error UI and a diagnostic-only log allowlist. No raw
error strings, URLs, request headers, payloads, account or device identifiers,
provisioning messages, passwords, verification codes or tokens are added to
diagnostic output. Existing unstructured backend logs are excluded in this
variant. The visible banner and window title distinguish it from upstream.

D2 retains the original 18 synthetic diagnostic tests and adds eight native
regressions for fixed service/operation categories derived from a typed
request error's destination. Only exact allowlisted HTTPS hosts and paths
select fixed labels. Unknown destinations stay other/unknown; missing URLs
stay unknown/unknown. Queries, fragments, user information and identifiers
never appear in output or determine an operation. No extra requests are made.
An account-request category does not distinguish authentication from tokens
sharing that route; an unknown label is not evidence about the failing stage.

Authentication, selected anisette provider, certificate validation, account
limits, signing, certificate/revocation prompts, keyring storage and device
installation code are unchanged. The locked dependency graph is unchanged;
one already-locked middleware dependency becomes directly visible to the app
so the diagnostic code can inspect typed errors. The underlying HTTP client
and its settings are NOT modified. In particular the upstream authentication
debug flag is never enabled.

This build may identify an error category; it is not a claimed fix. Categories
can be incomplete when an underlying library hides the cause. No Apple login
or device installation is performed by CI. All tests use synthetic errors.

The dedicated public CI workflow builds a candidate on a standard Windows
runner with frozen dependency locks and no signing credentials. It requires all
26 native synthetic tests to pass with no ignored tests, verifies the unchanged
protected source, then packages an unsigned AMD64 portable EXE, manifest,
corresponding public source, license notices and synthetic test summaries.
No failure logs or actual account/device logs are uploaded as artifacts.
The workflow does not install or launch the app. A passing build is not proof
that Apple authentication or installation on a real device succeeds.

Public candidate publication requires explicit consent. User logs and
account/device data must not be published. Human consent is also required
before running new software on a PC; a CI success is not that consent.
The original iloader installation has not been overwritten.

The app identifier is retained solely to keep upstream storage behavior
unchanged. Do not run the original and diagnostic app simultaneously. Do not
revoke certificates or remove existing device apps as a troubleshooting step.

Implementation: `apply.py fetch DESTINATION`, then `apply.py patch DESTINATION`.
The fail-closed recipe pins public source and verifies original Git blobs,
the exact patch surface and the unchanged locked dependency graph. Native
tests compile the actual added module inside the full app crate. Check the
matching CI run and manifest rather than assuming unbuilt source has passed.
