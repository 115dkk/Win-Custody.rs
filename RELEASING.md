# Releasing

## First release (0.1.0)

crates.io trusted publishing binds to a crate that already exists, so the
first version is published by hand with an API token:

1. On crates.io, sign in with GitHub, verify the account's email address,
   and create an API token with the `publish-new` scope.
2. From a clean checkout of `main` on Windows (so the verification build
   compiles the real code):

   ```console
   cargo login
   cargo publish --dry-run
   cargo publish
   ```

3. Revoke the token.
4. On `https://crates.io/crates/win-custody/settings`, add a trusted
   publisher: owner `115dkk`, repository `Win-Custody.rs`, workflow
   `release.yml`, environment `crates-io`.
5. Merge to `main`. The release workflow sees that the version is already on
   crates.io, skips publishing, and only tags the commit.

## Later releases

1. Bump `version` in `Cargo.toml`.
2. Turn the top of `CHANGELOG.md` into `## <version> - <YYYY-MM-DD>`.
3. Merge to `main` with CI green.

That is all. `release.yml` runs on every push to `main` and first checks
that the changelog has a dated entry for the manifest version. When that
version is not on crates.io yet, it runs the tests on Windows, publishes
through trusted publishing, and tags the commit `v<version>`. Otherwise it
only makes sure the tag exists; it does not start a Windows runner or touch
the `crates-io` environment.

A push to `main` that bumps the version without dating the changelog fails
the release workflow and publishes nothing. If a publish or the tag step
fails for another reason, re-run it from the Actions tab (`Run workflow` on
`main`); a version that is already published is skipped, and an existing
tag is left alone.
