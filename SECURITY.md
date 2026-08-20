# Security Policy

Numa is a from-scratch DNS resolver: the entire RFC 1035 wire protocol is
hand-rolled, with no DNS library at runtime. That makes the parser and the
resolution path the interesting attack surface, and it's where reports are most
welcome.

## Reporting a vulnerability

Report privately through GitHub's **[Report a vulnerability](https://github.com/razvandimescu/numa/security/advisories/new)**
form (Security → Advisories). It opens a private thread with the maintainer — do
not open a public issue for a suspected vulnerability.

Please include a description, affected version or commit, and the smallest input
or config that reproduces it. A failing fuzz input or a `dig`/`curl` one-liner is
ideal.

Expect an acknowledgement within a few days. Fixes ship on a coordinated
timeline: the advisory (and any CVE) is published once a fixed release is out.

Research done in good faith under this policy is welcome: test against your own
resolver, don't touch other people's, and we won't pursue you for it.

## Scope

In scope — anything that lets a network peer subvert the resolver:

- Wire-format parsing: `packet.rs`, `header.rs`, `question.rs`, `record.rs`,
  `svcb.rs`, `wire.rs`, `buffer.rs` (panics, over-reads, infinite loops,
  compression-pointer abuse).
- Resolution and validation: cache poisoning, DNSSEC chain-of-trust bypass,
  DNS rebinding filter bypass.
- The HTTP control plane and `.numa` proxy: authentication bypass, SSRF,
  request smuggling.
- Encrypted transports (DoT/DoH/ODoH) and the ODoH relay.

Out of scope:

- Vulnerabilities in third-party crates — those are tracked by `cargo audit`
  (run on every CI build) and Dependabot. Report an unpatched dependency
  advisory only if Numa's own use of it is exploitable.
- Deployment misconfiguration in a config *you* wrote — e.g. terminating TLS in
  front of the control plane incorrectly, or publishing it to the internet on
  purpose (see `recipes/dnsdist-front.md`). A default or shipped config that
  leaves the control plane reachable without a credential is **in scope**, not
  misconfiguration.
- Denial of service that requires privileged local access.

## What we run

Defense in depth is automated, not a substitute for review:

- `cargo audit` gates every build; Dependabot proposes dependency bumps monthly.
- `cargo fuzz` over the wire parser (`fuzz/`): a smoke run on every PR that
  touches it, a deeper weekly pass, seeded from a committed corpus. It has
  already caught real parser bugs.
- `clippy -D warnings` is a hard gate.

## Supported versions

Fixes land on `main` and in the next release. Only the latest release is
supported; please reproduce against `main` or the most recent tag before
reporting.
