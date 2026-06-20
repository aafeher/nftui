# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** — do not open a public
issue, pull request, or discussion that describes the problem.

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/aafeher/nftui/security/advisories/new)**
(also reachable from the repository's **Security** tab → **"Report a
vulnerability"**). That opens an advisory visible only to you and the
maintainers.

Please include:

- the affected version or commit,
- a description of the issue and its impact,
- reproduction steps or a proof of concept,
- any suggested fix or mitigation, if you have one.

What to expect:

- **Acknowledgement** within **3 business days** of your report.
- A **triage decision** within **7 days**; once confirmed, we share a fix or
  mitigation plan and a target date.
- **Coordinated disclosure** — a fixed release plus a published
  [GitHub Security Advisory](https://github.com/aafeher/nftui/security/advisories)
  that credits you unless you ask to remain anonymous.

Please allow up to **90 days** from your report before any public disclosure
(sooner once a fix has shipped).

## Supported Versions

Security fixes target the **most recent release**. Older releases do not receive
backported fixes — upgrade to the latest version.

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Model & Scope

nftui is a local terminal UI that reads and writes the kernel's nftables
ruleset over netlink. It has **no authentication or authorization of its own**
and relies entirely on operating-system privileges: it needs `CAP_NET_ADMIN`
(typically via `sudo`, or by granting the capability to the binary). Anyone who
can run nftui with that capability can already modify the firewall directly.

In scope — please report:

- a way to make nftui apply a ruleset change the operator did not intend (for
  example, input that injects unintended nftables statements);
- a crash or memory-safety issue triggered by untrusted kernel / ruleset data
  that nftui parses;
- a flaw in the release supply chain (the cosign signature, the SBOM, or the
  build-provenance attestation).

Out of scope:

- needing root / `CAP_NET_ADMIN` to change the firewall — that is by design;
- a `setcap`-granted binary being runnable by any local user — restrict that
  with your own `sudoers` or file-permission policy; nftui does not add its own
  access control. See the README's
  [Privilege model & deployment hardening](README.md#privilege-model--deployment-hardening)
  section for the recommended `sudoers` / `setcap` / PAM setup.
