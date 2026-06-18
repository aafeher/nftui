# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities **privately** — do not open a public
issue, pull request, or discussion that describes the problem.

Use GitHub's private vulnerability reporting: open the repository's **Security**
tab and choose **"Report a vulnerability"**. That creates an advisory visible
only to you and the maintainers.

Please include:

- the affected version or commit,
- a description of the issue and its impact,
- reproduction steps or a proof of concept,
- any suggested fix or mitigation, if you have one.

What to expect:

- acknowledgement of your report within a reasonable time,
- a triage decision and, once confirmed, a fix or mitigation plan,
- coordinated disclosure — a fixed release plus an advisory that credits you,
  unless you ask to remain anonymous.

Please allow a reasonable window to address the issue before any public
disclosure.

## Supported Versions

nftui is pre-1.0; security fixes target the **most recent release**. Older tags
do not receive backported fixes — upgrade to the latest version.

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
  access control.
