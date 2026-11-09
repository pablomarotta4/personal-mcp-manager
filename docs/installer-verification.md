# Verification and public releases

## Local acceptance

Build and test an unpacked source release on Apple Silicon macOS with local
socket access allowed:

```sh
npm ci --ignore-scripts
npm run build
npm run typecheck
python3 -m unittest discover -s scripts -p 'test_*.py'
node --test --test-concurrency=1 test/*.test.mjs
```

The automated installer matrix uses synthetic providers and covers Claude-only,
Codex-only and both-client selections, conditional projections, native restoration,
service lifecycle and source/manifest admission. It does not prove access to a
real provider account, a reboot or a colleague's computer.

`mcp-manager doctor` reports service, source, catalog and ownership results.
Provider access is opt-in with `doctor --safe-reads` under a selected signed
client. Preserve `NOT_TESTED`, `NEEDS_AUTH` and `UNSUPPORTED`; catalog metadata
alone is not evidence of provider authentication.

## Publication boundary

Publish a clean source export, never an installation directory or an entire
working tree. Keep the supplied `.gitignore`; generated builds, dependency trees,
private runtime, client config, credentials, transaction journals and logs are
not release inputs. Native binaries can embed the local build path and must be
built by the recipient rather than committed.

Create a source archive from the project root:

```sh
python3 scripts/package_release.py --output ../personal-mcp-manager-public-source.tar.gz
```

The command refuses to overwrite an existing archive. It exports an explicit
source allowlist, rejects private home
paths and recognized credential formats, verifies dynamic runtime import closure,
and emits a checksum and per-file manifest. The export includes
[third-party notices](../THIRD_PARTY_NOTICES.txt) for the bundled tool catalogs.
When updating a catalog, check the pinned upstream release and update its
attribution and license text in the same change. Tests use synthetic configuration.

Before uploading, inspect the intended Git file list and scan both filenames and
contents for environment-specific identifiers, emails, hostnames and credentials.
Also inspect existing Git history if using an existing repository. A `.gitignore`
does not remove files already tracked by Git. No repository history is included
in the source archive.

Extract the produced archive into a new directory, compare its manifest and
rerun its checks. Packaging and automated scans reduce accidental disclosure;
new integrations and real local configuration need their own review before
publication. Keep environment-specific migration adapters outside the public
source tree.
