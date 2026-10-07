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
- a pipe operation that blocks past its `PipeWait` deadline.

`win-custody` is not a sandbox. Code that a child runs with the rights it was
given is not a vulnerability in this crate.

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
reporter unless the reporter asks not to be named, and submits it to the
[RustSec advisory database](https://rustsec.org/).

There is no bug bounty.
