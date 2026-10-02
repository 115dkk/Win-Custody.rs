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
5. Push the tag `v0.1.0`. The release workflow sees that 0.1.0 is already
   on crates.io and stops before publishing.

## Later releases

1. Bump `version` in `Cargo.toml`.
2. Turn the top of `CHANGELOG.md` into `## <version> - <YYYY-MM-DD>`.
3. Merge to `main` with CI green.
4. Push the tag `v<version>` on that commit. `release.yml` checks that the
   tag, the manifest and the changelog agree, runs the tests on Windows, and
   publishes through trusted publishing.
