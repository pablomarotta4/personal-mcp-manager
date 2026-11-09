#!/usr/bin/env python3
"""Same-file, conditional migration. Never serialize proposal afterText."""
import copy
import hashlib
import hmac
import json
import os
import stat
from pathlib import Path
import re
import sys

import pilot
from pilot import SafeError, parse_editable, assert_semantics, read_private, private, locked, replace_config, write_private

TRANSPORT = {'type', 'command', 'args', 'env', 'env_vars', 'cwd'}
POLICY = {'enabled', 'required', 'startup_timeout_sec', 'startup_timeout_ms', 'tool_timeout_sec', 'enabled_tools', 'disabled_tools', 'tools'}
IDENTIFIER = re.compile(r'[A-Za-z0-9_-]+\Z')
HEADER = re.compile(r'(?m)^\[([^\n]+)\][ \t]*(?:#[^\n]*)?(?:\n|$)')
ENABLED = re.compile(r'(?m)^enabled[ \t]*=[ \t]*(true|false)[ \t]*(?:#[^\n]*)?(?:\n|$)')


def mac(value, token):
    return hmac.new(token.encode(), json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode(), hashlib.sha256).hexdigest()


def span(text, name):
    parse_editable(text)
    root = 'mcp_servers.' + name
    quoted = 'mcp_servers.' + json.dumps(name)
    roots = (root, quoted) if name.startswith(('mysql-', 'personal-manager-source-mysql-')) else (root,)
    headers = list(HEADER.finditer(text))
    selected = [m for m in headers if any(m.group(1) == candidate or m.group(1).startswith(candidate + '.') for candidate in roots)]
    if not selected or selected[0].group(1) not in roots:
        raise SafeError('TABLE_LAYOUT_UNSUPPORTED')
    for m in selected:
        header = m.group(1)
        if header == quoted or header.startswith(quoted + '.'):
            header = root + header[len(quoted):]
        if any(not IDENTIFIER.fullmatch(part) for part in header.split('.')):
            raise SafeError('TABLE_LAYOUT_UNSUPPORTED')
    indices = [headers.index(m) for m in selected]
    if indices != list(range(indices[0], indices[-1] + 1)):
        raise SafeError('TABLE_LAYOUT_UNSUPPORTED')
    end = headers[indices[-1]+1].start() if indices[-1]+1 < len(headers) else len(text)
    body_end = headers[indices[0]+1].start() if indices[0]+1 < len(headers) else len(text)
    return selected[0].start(), end, selected[0].end(), body_end


def rename(text, old, new):
    roots = (('mcp_servers.' + old, 'mcp_servers.' + new),
             ('mcp_servers.' + json.dumps(old), 'mcp_servers.' + json.dumps(new)))
    def replacement(match):
        for before, after in roots:
            if match.group(1) == before or match.group(1).startswith(before + '.'):
                return match.group().replace(before, after, 1)
        return match.group()
    return HEADER.sub(replacement, text)


def literal(value):
    if isinstance(value, bool): return 'true' if value else 'false'
    if isinstance(value, str): return json.dumps(value, ensure_ascii=True)
    if isinstance(value, (int, float)): return json.dumps(value, allow_nan=False)
    if isinstance(value, list): return '[' + ', '.join(literal(item) for item in value) + ']'
    if isinstance(value, dict): return '{' + ', '.join(json.dumps(k) + ' = ' + literal(v) for k, v in value.items()) + '}'
    raise SafeError('VALUE_UNSUPPORTED')


def validate(entry):
    if not isinstance(entry, dict) or set(entry) - TRANSPORT - POLICY:
        raise SafeError('SOURCE_UNSUPPORTED')
    if 'type' in entry and entry['type'] != 'stdio': raise SafeError('SOURCE_TRANSPORT_UNSUPPORTED')
    if not isinstance(entry.get('command'), str) or not entry['command']:
        raise SafeError('SOURCE_INVALID')
    for field in ('args', 'env_vars', 'enabled_tools', 'disabled_tools'):
        if field in entry and (not isinstance(entry[field], list) or not all(isinstance(x, str) for x in entry[field])):
            raise SafeError('SOURCE_INVALID')
    for field in ('enabled', 'required'):
        if field in entry and type(entry[field]) is not bool: raise SafeError('SOURCE_INVALID')
    for field in ('startup_timeout_sec', 'startup_timeout_ms', 'tool_timeout_sec'):
        if field in entry and (type(entry[field]) not in (int, float) or entry[field] <= 0): raise SafeError('SOURCE_INVALID')
    if 'env' in entry and (not isinstance(entry['env'], dict) or not all(isinstance(v, str) for v in entry['env'].values())):
        raise SafeError('SOURCE_INVALID')
    if 'cwd' in entry and not isinstance(entry['cwd'], str): raise SafeError('SOURCE_INVALID')
    if 'tools' in entry:
        tools = entry['tools']
        if not isinstance(tools, dict) or any(not isinstance(v, dict) or set(v) - {'enabled', 'approval_mode'} or ('enabled' in v and type(v['enabled']) is not bool) or ('approval_mode' in v and v['approval_mode'] not in ('auto', 'prompt', 'writes', 'approve')) for v in tools.values()):
            raise SafeError('TOOLS_POLICY_UNSUPPORTED')


def propose(text, id, url, helper, token):
    if not IDENTIFIER.fullmatch(id) or url != 'http://127.0.0.1:18765/mcp/' + id or not isinstance(helper, str) or not helper:
        raise SafeError('REGISTRATION_INVALID')
    parsed = parse_editable(text)
    servers = parsed.get('mcp_servers', {})
    source_id = 'personal-manager-source-' + id
    if source_id in servers: raise SafeError('SOURCE_COLLISION')
    entry = servers.get(id)
    validate(entry)
    start, end, body_start, body_end = span(text, id)
    body = text[body_start:body_end]
    lines = list(ENABLED.finditer(body))
    if len(lines) != (1 if 'enabled' in entry else 0): raise SafeError('ENABLED_LAYOUT_UNSUPPORTED')
    body = ENABLED.sub(lambda m: pilot.enabled_value(m.group(), 'false'), body) if lines else 'enabled = false\n' + body
    after = rename(text[:body_start] + body + text[body_end:], id, source_id)
    http = {k: copy.deepcopy(v) for k, v in entry.items() if k in POLICY}
    http.update(url=url, http_headers_helper=helper)
    registration = '[mcp_servers.' + id + ']\n' + ''.join(k + ' = ' + literal(v) + '\n' for k, v in http.items())
    # Append requires a line boundary; journal never stores this text.
    after += ('' if after.endswith('\n') else '\n') + registration
    expected = copy.deepcopy(parsed)
    expected['mcp_servers'][source_id] = dict(copy.deepcopy(entry), enabled=False)
    expected['mcp_servers'][id] = http
    assert_semantics(parse_editable(after), expected)
    record = {'version': 1, 'id': id, 'sourceId': source_id,
              'originalEnabledPresent': 'enabled' in entry, 'originalEnabledValue': entry.get('enabled'),
              'beforeHash': pilot.digest(text), 'sourceHmac': mac(expected['mcp_servers'][source_id], token),
              'httpHmac': mac(http, token), 'originalHmac': mac(entry, token)}
    record['recordHmac'] = mac(record, token)
    return {'beforeHash': pilot.digest(text), 'afterText': after, 'journal': record}


def authenticated(record, token):
    value = dict(record)
    signature = value.pop('recordHmac', '')
    if not hmac.compare_digest(signature, mac(value, token)) or value.get('version') != 1:
        raise SafeError('JOURNAL_INVALID')


def sync_directory(path, require_private=False):
    path = Path(path)
    if require_private: private(path, directory=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise SafeError('DIRECTORY_INVALID')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if opened.st_uid != os.getuid() or not stat.S_ISDIR(opened.st_mode) or (require_private and stat.S_IMODE(opened.st_mode) != 0o700):
            raise SafeError('DIRECTORY_INVALID')
        os.fsync(fd)
    finally:
        os.close(fd)


def clear_journal(journal, record):
    # Verify durability is available before removal; restore the credential-free
    # recovery record if the post-unlink sync fails.
    sync_directory(Path(journal).parent, require_private=True)
    Path(journal).unlink()
    try:
        sync_directory(Path(journal).parent, require_private=True)
    except Exception:
        write_private(journal, json.dumps(record).encode(), exclusive=True)
        raise


def apply(config, journal, proposal, token):
    private(Path(journal).parent, directory=True)
    if Path(config).resolve() == Path(journal).resolve(): raise SafeError('PATH_COLLISION')
    with locked(config):
        before = read_private(config).decode()
        if pilot.digest(before) != proposal['beforeHash']: raise SafeError('PROPOSAL_STALE')
        record = proposal['journal']
        authenticated(record, token)
        after = proposal['afterText']
        parsed = parse_editable(after)
        current = parse_editable(before)
        servers = parsed['mcp_servers']
        if mac(servers[record['id']], token) != record['httpHmac'] or mac(servers[record['sourceId']], token) != record['sourceHmac']:
            raise SafeError('PROPOSAL_INVALID')
        expected = copy.deepcopy(current)
        original = expected['mcp_servers'].pop(record['id'])
        if mac(original, token) != record['originalHmac']: raise SafeError('PROPOSAL_INVALID')
        expected['mcp_servers'][record['sourceId']] = dict(original, enabled=False)
        expected['mcp_servers'][record['id']] = servers[record['id']]
        assert_semantics(parsed, expected)
        write_private(journal, json.dumps(record).encode(), exclusive=True)
        sync_directory(Path(journal).parent, require_private=True)
        replace_config(config, before, after)
        sync_directory(Path(config).parent)
        assert_semantics(parse_editable(read_private(config).decode()), expected)


def rollback(config, journal, token):
    private(Path(journal).parent, directory=True)
    with locked(config):
        record = json.loads(read_private(journal))
        authenticated(record, token)
        text = read_private(config).decode()
        if pilot.digest(text) == record['beforeHash']:
            clear_journal(journal, record)
            return
        parsed = parse_editable(text)
        servers = parsed.get('mcp_servers', {})
        id, source_id = record['id'], record['sourceId']
        if source_id not in servers and mac(servers.get(id), token) == record['originalHmac']:
            clear_journal(journal, record)
            return
        if mac(servers.get(id), token) != record['httpHmac'] or mac(servers.get(source_id), token) != record['sourceHmac']:
            raise SafeError('ROLLBACK_MANAGED_ENTRY_CONFLICT')
        hs, he, _, _ = span(text, id)
        # The generated HTTP table has no standalone comments. Preserve notes
        # added later, including comments documenting the following table.
        notes = ''.join(line for line in text[hs:he].splitlines(keepends=True)
                        if not line.strip() or line.lstrip().startswith('#'))
        restored = text[:hs] + notes + text[he:]
        _, _, bs, be = span(restored, source_id)
        body = restored[bs:be]
        if len(list(ENABLED.finditer(body))) != 1: raise SafeError('ROLLBACK_ENABLED_CONFLICT')
        body = ENABLED.sub(lambda m: pilot.enabled_value(m.group(), literal(record['originalEnabledValue'])) if record['originalEnabledPresent'] else '', body)
        restored = rename(restored[:bs] + body + restored[be:], source_id, id)
        expected = copy.deepcopy(parsed)
        expected['mcp_servers'].pop(id)
        original = expected['mcp_servers'].pop(source_id)
        if record['originalEnabledPresent']: original['enabled'] = record['originalEnabledValue']
        else: original.pop('enabled')
        if mac(original, token) != record['originalHmac']: raise SafeError('ROLLBACK_ORIGINAL_CONFLICT')
        expected['mcp_servers'][id] = original
        assert_semantics(parse_editable(restored), expected)
        replace_config(config, text, restored)
        sync_directory(Path(config).parent)
        assert_semantics(parse_editable(read_private(config).decode()), expected)
        clear_journal(journal, record)


def main():
    print('LEGACY_MIGRATION_UNSUPPORTED', file=sys.stderr)
    return 2

if __name__ == '__main__':
    raise SystemExit(main())
