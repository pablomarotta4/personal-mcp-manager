# Personal MCP Manager

Run reviewed MCP servers behind one local service, shared by Claude Code and
Codex. Each colleague installs their own manager and uses their own existing
credentials. No account, cloud service or administrator access is required.

## Install

Supported host: **Apple Silicon macOS**. Install Python 3.11+, Node 22.12+ with
npm, and Apple’s Command Line Tools (`xcode-select --install`). The installer
checks interpreter permissions, architecture and selected client signatures.
Group-writable interpreters are refused; choose trusted per-user runtimes with
`--python` and `--node` rather than weakening integrity checks.

Unpack the release into a dedicated project folder. From that folder:

```sh
bash install.sh --client both --plan
```

Read the redacted source list and copy the displayed plan hash:

```sh
bash install.sh --client both --accept-plan <planHash>
```

Use `--client claude` or `--client codex` for a single app. Both clients must be
installed when explicitly selecting `both`. To migrate only one source, repeat
the same selection on both commands, for example:

```sh
bash install.sh --client claude --source claude:global:loki-stg --plan
```

Project configuration is opt-in with `--project /absolute/project/path`; the
installer does not recursively scan projects. Disabled and unsupported sources
remain direct. Profile names are generic examples; only reviewed commands and
source shapes are admitted. It verifies the candidate and starts the service **before**
replacing selected client registrations. Same-name sources with different
credentials or permissions get separate routes.

Check the result:

```sh
"$HOME/.local/bin/mcp-manager" status
"$HOME/.local/bin/mcp-manager" doctor
```

Reconnect the changed MCP servers or reopen your Claude/Codex sessions. Existing
sessions retain their old connections until they disconnect; changing a config
file does not terminate their processes.

## What it shares

[release/families.json](release/families.json) lists supported families;
[release/inputs.json](release/inputs.json) records pinned packages and accepted
example profile IDs, such as `grafana-dev`, `langfuse-traces`, `loki-stg` and
`mysql-primary-dev`. Use those names for the corresponding native registrations.
This edition targets
reviewed Grafana, Langfuse, Loki and standard npm MySQL sources. Custom wrappers
and other MCPs require their own admission and stay direct when unsupported.

Grafana can share a stateless backend. Loki, Langfuse and MySQL preserve session
isolation, signed client ownership and working-directory/environment rules.
Multiple simultaneous sessions can therefore still produce multiple backend
processes. The manager shares startup work where safe; it does not promise one
process per family or a fixed RAM saving.

Credentials remain in their original local source files or same-file disabled
backups. Runtime records contain source references and authenticated digests,
not copied provider secrets. Distribute the clean release archive, never an
installed runtime or client configuration.

## Daily use and recovery

Inspect activity without opening Claude or Codex:

```sh
mcp-manager status
mcp-manager connections
mcp-manager watch
mcp-manager watch --json --count 2
```

The monitor reads authenticated local status and does not invoke tools or start
backends. Sessions, in-flight requests, retained resources and backend processes
are separate measures. Tool counters reset when the manager restarts. Process
memory is summed RSS, not unique physical RAM. Old daemon versions show newer
metrics as unavailable until upgraded.

```sh
mcp-manager start
mcp-manager stop
mcp-manager mode default
mcp-manager mode manager
mcp-manager rollback
mcp-manager recover
mcp-manager uninstall
```

If the command is not on `PATH`, use `"$HOME/.local/bin/mcp-manager"`.

The per-user LaunchAgent `local.personal-mcp-manager` starts at login. It does
not restart itself after an intentional stop. `stop` requires a fresh drain and
proven cleanup; active or retained session resources can block it.

If the manager is down, routes pointing to it are unavailable. `mode default`
and `rollback` restore matching original native registrations offline, then
report backend/service cleanup separately. They preserve later user edits
rather than overwriting conflicts. `mode manager` verifies the service and
reapplies only the authenticated original selection. Reconnect clients after
either switch.

`doctor` reports installed files, service identity, catalog, source binding and
ownership separately. Provider calls are opt-in with `doctor --safe-reads`.
Stateful safe reads require execution beneath a selected signed Claude/Codex
client; otherwise the result is `NOT_TESTED`. Ordinary installation does not
prove access to every provider account.

An unchanged installation rerun does not rebuild or restart it. To update from a
new unpacked release:

```sh
mcp-manager update --source /absolute/path/to/unpacked-release
```

The update verifies source and policy compatibility, prepares a candidate and
requires maintenance checks before switching releases. The fresh installer
detects and refuses legacy installations: relocation is a separate cutover.

The public edition supports fresh portable installations and their authenticated
updates. Existing installations from other editions must be migrated separately;
this package does not ship machine-specific service conversion scripts. Installing
over a conflicting service, command or runtime is refused.

## Files and troubleshooting

Source can live anywhere. Installed program, runtime and artifacts live under
`~/Library/Application Support/Personal MCP Manager/`, with canonical versioned
releases under `app/releases/`. The stable command is `~/.local/bin/mcp-manager`.
The setup skill is [skills/mcp-manager-setup/SKILL.md](skills/mcp-manager-setup/SKILL.md).

See [troubleshooting](docs/setup-troubleshooting.md),
[verification](docs/installer-verification.md), and [LICENSE](LICENSE).
See [third-party notices](THIRD_PARTY_NOTICES.txt) for the licenses and
provenance of the bundled MCP tool catalogs.
The source release contains no installed runtime, credentials, client config,
private migration tools or generated binaries. Build on the destination computer;
keep `.gitignore` when creating a repository. See the verification guide for
publication checks and the limits of local testing.
