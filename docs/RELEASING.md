# Release procedure

A release is accepted only when the exact release tag has passed both GitHub
Actions workflows, `ci` and `e2e`. A green main-branch run, local test result,
or successful build alone is insufficient. Creating a tag starts validation;
publishing its GitHub Release happens afterward.

1. Finish the changes and run the relevant local checks described in
   [validation](../tests/README.md). Privileged tests must use the exact Babel
   revision pinned in `.github/workflows/e2e.yml`.
2. Commit from a clean worktree. Select an unused version and create its tag
   on that commit. Push the commit and tag; do not move a published tag.
3. Wait for both `ci.yml` and `e2e.yml` push runs for the **tag ref and commit**
   to finish with `success`. Record the tag, full commit SHA, run URLs and
   conclusions. Pending, cancelled, skipped, missing or failed runs do not
   satisfy this gate. Preserve failures and investigate them; rerunning until
   green is not evidence that a failure was fixed. A code fix needs a new
   commit and an unused tag, followed by validation of that tag.
4. Build archives from a clean export of that exact commit, using the release
   version and `-trimpath -buildvcs=false`. Include both binaries, documentation,
   packaging examples, `VERSION` and `BUILDINFO.json`; record the commit,
   toolchain, architecture and compatible Babel version. Normalize archive
   ownership and exclude local paths, credentials and deployment identifiers.
5. Check archive contents and SHA256 checksums. Smoke-test the actual amd64
   archive in the privileged environment. State separately whether arm64 was
   cross-built or tested natively. Babel is installed separately, not bundled.
6. Recheck that the remote tag still resolves to the recorded commit and its
   required runs still satisfy the gate. Only then publish the GitHub Release
   with its archives and `SHA256SUMS`, linking the successful runs. Describe
   remaining limitations accurately. Download the uploaded assets and verify
   their checksums before reporting publication complete.

Artifact preparation can run while CI is pending, but publication must wait
for both validation and artifact checks. Keep raw test evidence in ignored
local experiment storage; publish only sanitized release notes and artifacts.
