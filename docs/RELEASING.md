# Releasing NETREAPER

Releases are cut by the tag-triggered pipeline in
`.github/workflows/release.yml` (Rebuild Master Plan, Phase 5). Pushing a SemVer
tag builds, signs, checksums and publishes a GitHub release. There is no manual
upload step.

## Single source of truth

The version lives in the `VERSION` file at the repo root and is read by
hatchling (`[tool.hatch.version]` in `pyproject.toml`). The release job refuses
to run if the pushed tag does not match `VERSION`, so bump the file first.

## Cutting a release

1. Bump `VERSION` to the target version, for example `10.2.4`.
2. Update `CHANGELOG.md`.
3. Commit both on a branch, open a PR, merge to `main`.
4. Tag the merge commit and push the tag:

   ```bash
   git checkout main && git pull
   git tag v10.2.4
   git push origin v10.2.4
   ```

The pipeline then:

- builds the sdist and wheel with `python -m build`,
- smoke-installs the wheel and checks `import netreaper` and `netreaper --version`,
- writes `SHA256SUMS` (per-artifact SHA256),
- generates a CycloneDX SBOM for the release,
- signs the wheel, sdist and `SHA256SUMS` with Sigstore (keyless OIDC, no
  managed keys),
- creates the GitHub release with auto-generated notes and attaches the wheel,
  sdist, `SHA256SUMS`, the `.sigstore.json` bundles and the SBOM.

## Pre-release channels

A tag with a SemVer pre-release suffix is published as a GitHub pre-release and
its channel is derived from the suffix:

| Tag                 | Channel   | GitHub pre-release |
| ------------------- | --------- | ------------------ |
| `v10.3.0`           | stable    | no                 |
| `v10.3.0-rc.1`      | rc        | yes                |
| `v10.3.0-beta.2`    | beta      | yes                |
| `v10.3.0-alpha.1`   | alpha     | yes                |
| `v10.3.0-nightly`   | nightly   | yes                |

`VERSION` must carry the same suffix (for example `10.3.0-rc.1`) so the
tag/VERSION check passes.

Note the built artifact filenames are PEP 440-normalised, so the suffix loses its
hyphen and dot: tag `v10.3.0-rc.1` produces `netreaper-10.3.0rc1-py3-none-any.whl`
and `netreaper-10.3.0rc1.tar.gz`. The release globs handle this automatically;
just expect the normalised form when downloading a pre-release.

## Verifying a downloaded artifact

Checksums:

```bash
sha256sum -c SHA256SUMS
```

Sigstore signature (keyless, verified against the repo's tag workflow identity):

```bash
python -m pip install sigstore
sigstore verify github \
  --cert-identity "https://github.com/Nerds489/NETREAPER/.github/workflows/release.yml@refs/tags/v10.2.4" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle netreaper-10.2.4-py3-none-any.whl.sigstore.json \
  netreaper-10.2.4-py3-none-any.whl
```

Signing `SHA256SUMS` transitively authenticates every artifact: verify that one
bundle, then `sha256sum -c SHA256SUMS` proves the wheel, sdist and SBOM.

## Installing a release

```bash
pipx install https://github.com/Nerds489/NETREAPER/releases/download/v10.2.4/netreaper-10.2.4-py3-none-any.whl
```

## Rolling back a bad release

The pipeline only creates releases; retracting one is manual and deliberate.

```bash
# Remove the GitHub release and its assets, and drop the tag.
gh release delete v10.2.4 --yes --cleanup-tag
# (or, if the tag was not cleaned up above)
git push origin :refs/tags/v10.2.4
```

Then cut a fresh **patch** release with the fix:

- **Never delete-and-reuse a version number.** Bump to the next patch (for
  example `10.2.5`) and tag that. Downstreams and caches key on the version, and
  re-publishing a changed artifact under the same version is a supply-chain
  hazard.
- Sigstore transparency-log entries are **immutable**: you cannot unsign an
  artifact. Retraction means deleting the release/tag and superseding it, not
  revoking the signature.

