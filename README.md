# AltStore Classic — experimental HealthKit build

This repository contains a reproducible source adaptation of AltStore Classic for preserving the HealthKit App ID capability during re-signing. It is not an official AltStore release.

Only source code, build instructions and synthetic tests belong here. Never commit signing certificates, private keys, provisioning or pairing files, device identifiers, accounts, application data or personal notes.

Public commits must use a synthetic GitHub no-reply author and committer identity. The privacy gate checks the entire candidate ancestry as well as the source-file allowlist. Do not create commits through a client that silently selects a personal account email.

The update is not ready for installation until the native capability tests, iPhone build and package inspection pass. Preserve the previously installed application and its data.

Upstream: https://github.com/altstoreio/AltStore/tree/classic
HealthKit mapping reference: https://github.com/rileytestut/AltSign/pull/45

## Scope

The reviewed upstream revision is pinned in `upstream.json`; the adaptation preserves the original HK Test bundle identifier, display name, app groups, widget and signing flow. HK4 build 7003 is newer than HK3 build 7002, HK2 build 7001 and the original HK Test build 6501. No device or server ID is baked into the distributable. Personal signing must preserve the owner's existing device/server/certificate metadata privately; none belongs in this repository or its public artifacts.

The capability change maps the Boolean `com.apple.developer.healthkit` entitlement to the existing legacy App ID feature `HK421J6T7P` in both directions. Secondary HealthKit arrays/background entitlements are not converted into fabricated portal features. Existing entitlement/profile intersection remains intact.

HK3 additionally wires the existing AltSign refresh callback in the iPhone AuthenticationOperation. Each refresh fetches fresh data through the existing selected transport and context. Fetch failures are propagated without a stale-data success fallback; cancelled, completed or deallocated owners return cancellation. This is wiring of an upstream-supported mechanism, not a replacement authentication protocol. It does not establish that every HTTP 503 is caused by this omission or that a real account can sign in.

HK4 additionally forwards the current anisette provider's optional `user_agent` to AltSign after a successful header fetch, matching upstream proposal [AltStore PR 1851](https://github.com/altstoreio/AltStore/pull/1851). The pinned source already decoded this field but did not set AltSign's existing `authenticationUserAgent` property. A nil value retains AltSign's supported fallback. No new user agent, provider, device identity or authentication protocol is fabricated. Baseline/source hash checks and a native harness compiling the exact inserted assignment cover this narrow change; they are not a real Apple login or a guarantee against HTTP 503.

Certificate validation, account limits, existing selected transports, signing flow and security checks remain unchanged. There are no entitlement changes outside the HealthKit mapping. This does not promise to solve every Apple authentication error.

## Reproduce and verify

1. Run `python3 scripts/privacy_gate.py` and `python3 -m unittest discover -s tests -v`.
2. Fetch public pinned sources with `python3 scripts/fetch_source.py upstream`.
3. The macOS workflow compiles the synthetic native capability harness against the original source and requires exactly the two missing-HealthKit checks to fail. It then applies the adaptation, recompiles the same harness and requires all 14 checks to pass.
   The original authentication and anisette-fetch sources must match their pinned Git blobs and lack the respective wiring. The exact production closure inserted into the real iPhone source is compiled in a separate native Swift harness, requiring 18 synthetic checks for fresh results, context, errors and owner cancellation/lifetime. The exact provider user-agent assignment is compiled in an additional harness requiring 16 identity checks. These use doubles, not a live Apple session or the complete authentication SDK.
4. The workflow builds the full iPhone app without a developer certificate, adds only local ad-hoc signatures, and verifies the ARM64 binaries, unchanged app identity, compiled capability mapping and archive integrity.
5. The candidate artifact contains an IPA, manifest, native check logs and complete corresponding source with the upstream licenses. An ad-hoc signature is not a personal developer signature; installation still requires the owner's existing signing workflow on their device.

No real Apple login, certificate import, data migration or physical HealthKit test takes place in CI. These remain explicit device checks. Do not uninstall an existing HK Test/Pivot installation, revoke certificates, randomize bundle IDs or overwrite app data as a shortcut.

Public standard GitHub-hosted runners only; no paid runners, external signing service, persistent credentials or deployment secrets are configured.

## License and provenance

Adaptation scripts and synthetic tests: AGPL-3.0-only. Upstream AltStore and dependencies retain their original licenses and notices. The workflow fetches their exact commits and includes their complete corresponding source in the candidate artifact; the build recipe and transformation are included here. This is an experimental downstream build, not an official AltStore release or an assurance of Apple approval.
