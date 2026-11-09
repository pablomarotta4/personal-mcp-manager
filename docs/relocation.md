# Existing installations

This public edition supports fresh portable installations and authenticated updates
of those installations. Machine-specific migration adapters are not distributed.

An existing service, runtime or command owned by another edition is a conflict,
not permission to replace it. Keep that installation and its credentials intact.
Use its own offline restoration/recovery commands or a separate reviewed migration.
Do not rename a legacy runtime or create an installation descriptor around it.

For an installation created by this edition, use:

```sh
mcp-manager update --source /absolute/path/to/unpacked-release
```

The update verifies the candidate before draining the owned service. Active or
retained resources can block maintenance; close the affected client sessions and
retry. Never delete ownership records or stop unrelated processes to force it.
