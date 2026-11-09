"""Shared, protected readers for the Codex config and pinned external-MCP sources."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tomllib

from owner_watch import strict_json
from pilot import SafeError


MAX_CONFIG_BYTES = 1048576
MAX_CLAUDE_CONFIG_BYTES = 16 * 1048576
MAX_PLUGIN_METADATA_BYTES = 262144
MAX_PLUGIN_SOURCE_BYTES = 1048576


def protected_read(path, maximum, *, private=False, error_code="SOURCE_INPUT_INVALID"):
    """Walk every component using retained no-follow directory descriptors."""
    path = Path(path)
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise SafeError(error_code)
    descriptors = []

    def checked(fd, directory):
        info = os.fstat(fd)
        if (info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022
                or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
            raise SafeError(error_code)
        return info

    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(fd)
        checked(fd, True)
        for component in path.parts[1:-1]:
            fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
            checked(fd, True)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        descriptors.append(fd)
        before = checked(fd, False)
        if private:
            if before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600:
                raise SafeError(error_code)
            parent = os.fstat(descriptors[-2])
            if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
                raise SafeError(error_code)
        if before.st_size > maximum:
            raise SafeError(error_code)
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(fd)
        if private and (
            after.st_uid != os.getuid()
            or stat.S_IMODE(after.st_mode) != 0o600
            or stat.S_IMODE(os.fstat(descriptors[-2]).st_mode) != 0o700
        ):
            raise SafeError(error_code)
        if len(data) > maximum or (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise SafeError(error_code)
        # Reopen from the root to catch namespace replacement during the read.
        for index, descriptor in enumerate(descriptors):
            prefix = Path("/") if index == 0 else Path("/").joinpath(*path.parts[1:index + 1])
            visible = prefix.lstat()
            held = os.fstat(descriptor)
            if (
                (visible.st_dev, visible.st_ino) != (held.st_dev, held.st_ino)
                or visible.st_uid not in (0, os.getuid())
                or visible.st_mode & 0o022
            ):
                raise SafeError(error_code)
            checked(descriptor, index < len(descriptors) - 1)
        return bytes(data)
    except Exception:
        raise SafeError(error_code) from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def read_config(config_path, *, reader=None):
    """Return protected UTF-8 TOML text and its decoded mapping."""
    read = reader or protected_read
    try:
        text = read(config_path, MAX_CONFIG_BYTES).decode("utf-8")
        return text, tomllib.loads(text)
    except Exception:
        raise SafeError("SOURCE_INPUT_INVALID") from None


def read_claude_config(config_path, *, reader=None):
    """Return a complete, protected Claude JSON config up to the supported limit."""
    read = reader or protected_read
    try:
        text = read(config_path, MAX_CLAUDE_CONFIG_BYTES).decode("utf-8")
        value = strict_json(text)
        if type(value) is not dict:
            raise ValueError()
        return text, value
    except Exception:
        raise SafeError("SOURCE_INPUT_INVALID") from None


def _decode_plugin_source(root, client, read):
    root = Path(root)
    metadata_path = ".claude-plugin/plugin.json" if client == "claude" else ".codex-plugin/plugin.json"
    metadata = read(root / metadata_path, MAX_PLUGIN_METADATA_BYTES)
    decoded = strict_json(metadata)
    identifier = root.parent.name + "@" + root.parent.parent.name
    version = decoded.get("version")
    if (not isinstance(version, str) or not version or len(version) > 128
            or decoded.get("name") != root.parent.name):
        raise ValueError()
    source_path = decoded.get("mcpServers", ".mcp.json")
    if source_path not in (".mcp.json", "./.mcp.json"):
        raise ValueError()
    source = strict_json(read(root / source_path, MAX_PLUGIN_SOURCE_BYTES))
    if (type(source) is not dict or set(source) != {"mcpServers"}
            or type(source["mcpServers"]) is not dict):
        raise ValueError()
    digest = hashlib.sha256(metadata).hexdigest()
    return dict(id=identifier, version=version, path=str(root), sourcePath=source_path,
                metadataSha256=digest, servers=source["mcpServers"], reviewed=False)


def read_plugins(*, reader=None, client=None, roots=None):
    """Read client plugin snapshots as unreviewed; no marketplace pins ship here."""
    read = reader or protected_read
    if client is not None:
        if client not in ("claude", "codex"):
            raise SafeError("SOURCE_INPUT_INVALID")
        # `roots` comes from the selected client's discovered, installed plugin roots.
        # Do not fall back to this machine's configured plugin paths in portable mode.
        if roots is None:
            raise SafeError("SOURCE_INPUT_INVALID")
        try:
            plugins = []
            for root in roots:
                plugins.append(_decode_plugin_source(root, client, read))
            return plugins
        except Exception:
            raise SafeError("SOURCE_INPUT_INVALID") from None
    return []


def read_source_inputs(config_path, *, reader=None, client=None, plugin_roots=None):
    """Return the protected config and any client plugin snapshots."""
    if client is None:
        _, config = read_config(config_path, reader=reader)
        return config, read_plugins(reader=reader)
    if client == "claude":
        _, config = read_claude_config(config_path, reader=reader)
    elif client == "codex":
        _, config = read_config(config_path, reader=reader)
    else:
        raise SafeError("SOURCE_INPUT_INVALID")
    return config, read_plugins(reader=reader, client=client, roots=plugin_roots)
