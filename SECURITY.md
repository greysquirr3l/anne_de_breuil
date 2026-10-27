# Security Policy

## Supported Versions

`anne-de-breuil` is a pre-1.0 tool. Fixes land on `main` and are released
as a tagged release; there are no long-term-support branches.

| Version | Supported |
| ------- | --------- |
| 0.4.x | yes |
| 0.3.x and anything older | no |

`0.4.0` is the current release. It is the first release distributed on
crates.io (`cargo install anne-de-breuil-cli`) as well as through GitHub
Releases, and it raises the minimum supported Rust version to 1.99.1 —
build from source with a 1.99.1-or-newer toolchain.

## Reporting a Vulnerability

Report suspected vulnerabilities privately through GitHub's
[private vulnerability reporting][pvr] on this repository, which opens a
confidential advisory visible only to the maintainers.

[pvr]: https://github.com/greysquirr3l/anne_de_breuil/security/advisories/new

Please include:

- what the issue is and what an attacker gains from it,
- the version or commit you tested against,
- reproduction steps, and
- any crash output or collector output verbatim.

Do not open a public issue for a suspected vulnerability.

## What to Expect

- Acknowledgement within a few days.
- An assessment of the report once reproduced, and a decision on whether
  it is in scope.
- A fix and a release, or a written explanation of why the report is
  declined.

## Scope

This tool enumerates a host's listening ports, correlates them with the
processes and services that own them, and reports the effective host
firewall policy. It is a read-only inventory tool: it collects
observations, and it does not itself alter the host's state.

In scope:

- collector behaviour that reads or transmits data beyond what the
  documented invocation asks for,
- credential handling — SSH private keys, keyring entries, and passphrases
  must never appear in logs, reports, or collector output at any verbosity,
- the release pipeline producing an artifact that does not correspond to
  the source it claims to come from,
- the crates.io packages (`anne-de-breuil`, `anne-de-breuil-cli`)
  differing from the tagged source they were published from, or a
  published crate shipping a dependency the tag did not carry,
- a report that misrepresents the host's actual exposure, in a way that
  leads an operator to a wrong conclusion about their security posture.

Out of scope:

- findings that are really the behaviour of the tool being scanned (an
  open port on the target host is the target host's business),
- denial of service against a scanned host,
- missing hardening on the machines running the orchestrator, unless the
  tool itself introduced it.

## Credential Handling

The tool never writes credentials to disk, stdout, stderr, or any report
format. Concretely:

- SSH private keys are read from a key file, an `ssh-agent`, or the OS
  keyring, and are passed to the SSH client in memory only.
- Passphrases are read from the environment and never echoed.
- Collector output is redacted before it leaves the host.
