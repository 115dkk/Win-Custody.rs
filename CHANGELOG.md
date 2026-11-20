# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
follows [Semantic Versioning](https://semver.org/).

## 0.1.6 - 2026-11-21

### Added

- `JobLimits::die_on_unhandled_exception` makes unhandled exceptions end job
  processes without leaving them waiting behind the Windows Error Reporting
  fault dialog.
- `AppContainerAccess::ReadExecute` and `ReadWriteExecute` grant execute access
  for executables and DLLs, with or without write and delete access.
- `AppContainerProfile::ensure_path_access` checks the profile SID and ALL
  APPLICATION PACKAGES before writing a persistent path grant, so existing
  access does not require changing or rewriting the DACL.
- `Process::has_capability` reports whether an AppContainer process token holds
  a named Windows capability.

### Changed

- `SECURITY.md` says when an advisory is also submitted to RustSec: when the
  defect is of a kind RustSec tracks, and the crate meets the notability bar
  RustSec's maintainers apply (a dependent crate from a different author, more
  than 1,000 recent downloads, or 100,000 downloads in total), which it does
  today. GHSA-4cxw-9fpf-wwmp gives an attacker nothing they did not already
  have, so it stays a GitHub advisory only.

## 0.1.5 - 2026-11-16

### Changed

- `SECURITY.md` no longer promises a RustSec submission for every confirmed
  vulnerability. Confirmed vulnerabilities are published as GitHub security
  advisories, which GitHub reviews for the advisory database that Dependabot
  reads.

### Fixed

- `PrivilegeGuard` disabled its privilege when dropped, even when the
  privilege was already enabled before the guard was created or another guard
  for it was still alive. A guard now leaves an already enabled privilege as
  it was, and guards for the same privilege are counted, so the privilege is
  disabled only when the last of them is dropped. Before, a dropped guard for
  `SeChangeNotifyPrivilege`, which every token has enabled, left the process
  without it, and a child started afterwards could no longer pass through
  directories it may not list; an AppContainer child whose working directory
  lies under the user profile then failed to start with access denied.

## 0.1.4 - 2026-11-16

### Fixed

- `Launch::spawn_in_job` created the child first and assigned it to the job
  afterwards. If the parent was killed between the two steps, the child stayed
  behind, suspended and outside the job, so it outlived a kill-on-close job.
  The child is now created inside the job with
  `PROC_THREAD_ATTRIBUTE_JOB_LIST` and never exists outside it
  (GHSA-4cxw-9fpf-wwmp).

### Added

- `Launch::spawn_suspended_in_job`: creates the child suspended and already a
  member of the job, for callers that prepare the child before resuming it.
  Use it instead of `Launch::spawn_suspended` followed by `Job::assign`.

### Changed

- `Launch::spawn_in_job` needs Windows 10 or Windows Server 2016, where
  `PROC_THREAD_ATTRIBUTE_JOB_LIST` was introduced. On older systems it fails
  instead of assigning the child after creating it.
- When the job refuses the child, for example at its active-process limit,
  `Launch::spawn_in_job` fails without creating a process. Before, it created
  the child and terminated it.

## 0.1.3 - 2026-11-12

### Added

- `AppContainerProfile`: creates or opens a named AppContainer profile with
  the capabilities you name, reports whether it was created
  (`was_created`), grants it access to files and directories (`grant_path`)
  and deletes it (`delete`). Contributed by @senamakel in #5.
- `Launch::app_container`: starts the child in that profile's AppContainer,
  together with the explicit handle list and the suspended create, job
  assignment and resume order of `spawn_in_job`. AppContainer launches are
  opt-in; a `Launch` without it confines nothing, as before. It cannot be
  combined with `Launch::as_user`.
- `Process::is_app_container`: whether a process runs with an AppContainer
  token.

## 0.1.2 - 2026-10-29

### Added

- `PrimaryToken::user_sid_string`: the token user's SID in string form, for
  example the user logged on to the session of a token from
  `PrimaryToken::for_session_user`. Until now only the calling process's own
  user SID was available (`current_user_sid_string`).

## 0.1.1 - 2026-10-05

### Added

- `SECURITY.md`: report vulnerabilities through GitHub's private
  vulnerability reporting. The file now ships in the package.

## 0.1.0 - 2026-10-02

First release.

### Added

- `Launch`: creates a child with an explicit `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`,
  optional standard handles, a sorted Unicode environment block, a working
  directory, a desktop, and an optional primary token (`CreateProcessAsUserW`).
  `spawn_in_job` creates the child suspended, assigns it to a job, then resumes
  it. `inherit` returns the handle value the child will see.
- `SuspendedChild`: terminates the child when dropped without being resumed.
- `Job` and `JobLimits`: kill-on-close, active-process and commit limits, with
  optional security.
- `Process`: fixed rights sets, adoption of a `std::process::Child`, elevation
  through the shell's `runas` verb, PID-reuse-safe identity (creation time),
  exit code, image path, session.
- `PrimaryToken`: duplicate of the own token, `WTSQueryUserToken`, session
  moves.
- `SecurityDescriptor` (from SDDL, tree application), `ObjectSecurityDescriptor`
  with validated owner and DACL views, `OwnedSid`, `PrivilegeGuard`,
  `current_user_sid_string`, `current_token_is_member_of`.
- `PipeServer` and `PipeClient`: single-instance, local-only, overlapped byte
  pipes with deadlines, peer-exit cancellation and peer PID queries.
- `NamedMutex` with explicit security.
- Session helpers: `current_session_id`, `process_session_id`,
  `active_console_session_id`, `session_processes`.
- `wait`, `anonymous_pipe`, `null_device`, `read_to_end_bounded`.
