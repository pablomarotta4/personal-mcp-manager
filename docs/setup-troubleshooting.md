# Setup and recovery

Report fixed error codes and redacted plan/doctor results. Client configuration,
provider responses and environment dumps can contain credentials; do not share
them.

## Prerequisites and discovery

- `APPLE_SILICON_MACOS_REQUIRED`, `PYTHON_3_11_REQUIRED`, `NODE_22_12_REQUIRED`:
  install the required host/runtime version. Intel Macs, Linux and Windows are
  not supported by this release.
- `PYTHON_TRUSTED_3_11_REQUIRED` / `PYTHON_TRUST_UNVERIFIED`: choose a trusted
  per-user interpreter with `--python /absolute/python3`. `MCP_MANAGER_PYTHON`
  selects the interpreter starting `install.sh`; `--python` selects the installed
  manager interpreter. Do not remove integrity checks.
- `REQUESTED_CLIENT_NOT_FOUND` / `CLIENT_OWNER_UNVERIFIED`: install the selected
  signed client or choose only the client that is installed.
- `CODEX_PLUGIN_ROOT_MISSING` / `CODEX_PLUGIN_ROOT_INVALID`: repair the selected
  client's incomplete or ambiguous enabled plugin, then rerun `--plan`. Do not
  guess another cached version.
- `NO_SUPPORTED_SOURCES_SELECTED`: inspect the redacted rows. A matching name
  does not make an arbitrary command or custom wrapper supported.

Include an absolute `--project` only for projects in scope. Global, project and
plugin sources are distinct. A plugin source is disabled only when its exact
replacement is verified.

## Refused installation

`--plan` discovers sources without editing client settings. Accept exactly its
displayed selections and hash. Source or release changes need a new plan;
editing a receipt is not a workaround.

`INSTALLATION_ROOT_CONFLICT`,
`LAUNCHAGENT_LABEL_CONFLICT`, `COMMAND_PATH_CONFLICT` and `PORT_IN_USE` preserve
the existing installation/foreign file. Inspect its owner and location; do not
delete it or start a second daemon to bypass the refusal.

Dependency hash failures require an intact trusted release/download. Do not
accept a newly observed local digest as a replacement pin. Acquisition uses
fresh private workspaces rather than inherited npm/uv caches.

`OWNER_SOCKET_PATH_TOO_LONG` means the runtime exceeds the macOS Unix-socket
path limit. Stateful installation at unusually long home paths is currently
unsupported. Do not bypass socket ownership or symlink runtime directories.
Changing the source checkout's name does not shorten the installed runtime.

## Interrupted installation

Exit code 3 means authenticated recovery is required:

```sh
"$HOME/.local/bin/mcp-manager" recover
```

If the stable command was not yet published, use the canonical release CLI and
the installation descriptor; inspect `python3 scripts/mcp_manager.py --help`
for its arguments. Do not create a new token or edit the journal. Recovery
restores matching projections and reports uncertain cleanup separately. A phase
without sufficient ownership proof needs inspection, not runtime deletion.

## Manager down or native configuration wanted

```sh
"$HOME/.local/bin/mcp-manager" mode default
```

Restoration works offline. Reconnect affected client MCPs afterward.
`mode manager` verifies the owned service and reapplies the original selection.
Changed credentials need re-admission; stale authenticated records are refused.

A rollback conflict means a file changed after projection. Preserve later user
edits and inspect the specific source; do not overwrite unrelated config with a
full old copy.

## Stop, doctor and removal

Retained sessions can block stop with no active calls. Close/reconnect their
specific client sessions, then retry. Do not kill every Node/Python process or
delete ownership records. A failed drain resumes normal service when possible.

`doctor --safe-reads` uses fixed provider reads. `SIGNED_CLIENT_REQUIRED` means
run beneath the selected signed client. `NEEDS_AUTH` means the attempted provider
path rejected authentication. `NOT_TESTED` is not a pass. Active ownership needs
identity inspection, not forced cleanup.

`uninstall` restores matching native routes first and removes only matching
owned service/command/skill files after cleanup proof. Recoverable program,
runtime or artifact data may remain; inspect the result before claiming complete
removal.

## Monitoring

`mcp-manager status` is a bounded authenticated local read. `connections` adds
per-route session/request summaries when the running daemon supports them;
`watch --count 2 --json` emits two machine-readable snapshots and exits.
Monitoring never calls a provider tool or opens an MCP session.

`UNAVAILABLE` means a metric could not be established, not zero usage. An older
daemon can expose requests, retained resources and traffic while omitting session
counts. `DOWN` means the owned service/status could not be reached; inspect the
fixed reason before restarting anything. A new daemon generation resets tool
counter deltas. RSS sums resident process pages and can count shared pages more
than once; it excludes MCPs outside the verified manager process tree.

This public edition monitors installations created by its own installer. It does
not import or convert another edition's private runtime. Preserve a conflicting
installation and use a separate, reviewed migration rather than overwriting it.
