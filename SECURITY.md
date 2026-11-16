# Security Policy

`win-custody` is a personal project maintained by
[@115dkk](https://github.com/115dkk), who is responsible for its security and
handles every vulnerability report for it.

## Scope

The crate's own code, including:

- unsoundness: undefined behaviour reachable through the safe API;
- a child process that inherits a handle the caller did not name, outlives a
  kill-on-close job, or runs under a token other than the one requested;
- a security descriptor, pipe, or mutex that admits principals the caller's
  SDDL did not grant, or a peer identity check that reports the wrong
  process;
- a pipe operation that blocks past its `PipeWait` deadline;
- with `Launch::app_container`: a child that does not run in the requested
  AppContainer, holds a capability that was not requested, or gets more
  access from `AppContainerProfile::grant_path` than was asked for.

Sandboxing is opt-in. A `Launch` without `app_container` confines nothing, so
code that a child runs with the rights it was given is not a vulnerability in
this crate. Escaping an AppContainer that was set up as requested is a Windows
issue, not this crate's.

## Supported versions

Only the newest version published on
[crates.io](https://crates.io/crates/win-custody) gets security fixes.

## Reporting a vulnerability

Report it privately through
[GitHub's private vulnerability reporting](https://github.com/115dkk/Win-Custody.rs/security/advisories/new).
Do not open a public issue, discussion, or pull request for a suspected
vulnerability.

A useful report names the crate version, the Windows version, and a minimal
program that shows the problem.

## What happens next

This project is maintained in spare time, so there is no guaranteed response
time. The maintainer reads every report and answers in the report's private
thread. A confirmed vulnerability is fixed in a new release on crates.io, and
the maintainer then publishes a GitHub security advisory that credits the
reporter unless the reporter asks not to be named. GitHub reviews published
advisories for the
[GitHub Advisory Database](https://github.com/advisories), which is where
Dependabot alerts come from.

An advisory is also submitted to the
[RustSec advisory database](https://rustsec.org/), which `cargo audit` and
`cargo deny` read, when both of these hold:

- The defect is of a kind RustSec
  [tracks](https://github.com/rustsec/advisory-db/blob/main/CONTRIBUTING.md#criteria),
  such as code execution, memory corruption, privilege escalation or file
  disclosure. A defect that gives an attacker nothing they did not already
  have stays a GitHub advisory only. GHSA-4cxw-9fpf-wwmp, which leaks a
  suspended process and the handles it inherited, is one of those.
- The crate meets the notability bar RustSec's maintainers
  [apply](https://github.com/rustsec/advisory-db/pull/3017#issuecomment-5254097043):
  at least one crate on crates.io from a different author depends on it, or it
  has more than 1,000 recent downloads, or 100,000 downloads in total. RustSec
  declines advisories for crates below it. In November 2026 `win-custody`
  meets it, with four dependent crates from three other authors and about
  7,400 recent downloads.

There is no bug bounty.
