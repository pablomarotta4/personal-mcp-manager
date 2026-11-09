---
name: mcp-manager-setup
description: Use when installing Personal MCP Manager for Claude Code or Codex, switching its MCP routes back to native configuration, or recovering an interrupted local installation.
---

# Personal MCP Manager setup

Use the release installer and CLI. Each computer uses its own existing client
configuration and provider credentials.

1. Locate the unpacked release containing `install.sh`, `README.md` and
   `release/families.json`. Read its README and confirm the selected clients.
   If `~/Library/Application Support/Personal MCP Manager/installation.json`
   already exists, inspect the installed CLI first; do not create a second daemon.
2. Run `bash install.sh --client CLIENT --plan` from the release, where CLIENT
   is `claude`, `codex` or `both`. Include `--project` only for an in-scope
   project. Use repeatable `--source CLIENT:SCOPE:NAME` selectors for a limited
   migration. Read the redacted plan: selected and unsupported rows must account
   for the requested sources. A familiar name does not admit an arbitrary command.
3. When installation is authorized, use the same selections with
   `--accept-plan HASH` and the current displayed hash. The installer owns
   downloads, admission, service registration and conditional client edits.
   Verify its receipt and on-disk readback. Do not separately edit client configs
   or copy provider credentials into a manager file.
4. Run `"$HOME/.local/bin/mcp-manager" status` and `doctor`. Report installed,
   service, catalog, source and ownership results separately. Use
   `doctor --safe-reads` for requested provider validation; stateful checks need
   selected signed-client ancestry. Preserve `FAIL`, `NEEDS_AUTH`, `UNSUPPORTED`
   and `NOT_TESTED`. Catalog discovery is not provider authentication proof.
5. Report which sources use the manager and which remain direct, then reconnect
   affected client MCPs. Existing sessions can retain native processes after
   configuration changes. Stateful sessions can legitimately keep multiple
   backend processes.

For an outage or a return to native MCPs, run
`"$HOME/.local/bin/mcp-manager" mode default` (or `rollback`) before investigating
service cleanup. Restoration works offline and only for matching owned
projections. `mode manager` verifies the service and restores only the original
authenticated selection. Reconnect clients after either switch.

Use `recover` after interruption and `uninstall` for removal. Follow the
release's `docs/setup-troubleshooting.md` for fixed refusal codes. Retained
resources or ownership conflicts block maintenance: preserve the evidence.
Never kill unrelated sessions, delete ownership records, invent replacement
hashes or overwrite later user edits to force a successful result.

For an authorized update, use `mcp-manager update --source /absolute/release`
with an unpacked trusted release. The CLI stages and verifies the candidate
before its conditional cutover; do not rerun fresh setup over an existing manager.

Finish with actual receipt/check results, selected client/source counts,
remaining direct sources, reconnect instructions and pending cleanup. Keep
config values, environment dumps and provider secrets out of shared output.
