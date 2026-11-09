"""Reviewed npm MySQL effective environment; all values remain in memory.

The parser mirrors dotenv 16's parse(), including exports, multiline quoted
values, empty values and last duplicate wins. A pinned entry suppresses a second
.env read only after this effective environment has been admitted.
"""
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re

from owner_watch import Identity, CwdBinding, OwnerError, REVIEWED_CODEX, claude_path
from source_inputs import protected_read

MYSQL_KEYS = frozenset('''ALLOW_DDL_OPERATION ALLOW_DELETE_OPERATION ALLOW_INSERT_OPERATION ALLOW_UPDATE_OPERATION
ENABLE_LOGGING ENABLE_PII_REDACTION IS_REMOTE_MCP MULTI_DB_WRITE_MODE MYSQL_BIG_NUMBER_STRINGS
MYSQL_CONNECTION_STRING MYSQL_CONNECT_TIMEOUT MYSQL_DATE_STRINGS MYSQL_DB MYSQL_DISABLE_READ_ONLY_TRANSACTIONS
MYSQL_HOST MYSQL_PASS MYSQL_PORT MYSQL_QUEUE_LIMIT MYSQL_SOCKET_PATH MYSQL_SSL MYSQL_SSL_CA MYSQL_SSL_CERT
MYSQL_SSL_KEY MYSQL_SSL_REJECT_UNAUTHORIZED MYSQL_TIMEZONE MYSQL_USER NODE_ENV PII_ALLOW_INTROSPECTION
PII_ALLOW_REFERENCES PII_ALLOW_SELECT_STAR PII_BLOCK_INTROSPECTION PII_EXTRA_COLUMNS PII_EXTRA_COLUMN_PATTERNS
PII_REDACT_JSON_STRINGS PORT REMOTE_SECRET_KEY SCHEMA_DDL_PERMISSIONS SCHEMA_DELETE_PERMISSIONS
SCHEMA_INSERT_PERMISSIONS SCHEMA_UPDATE_PERMISSIONS VITEST npm_package_version'''.split())
INHERITED = MYSQL_KEYS | frozenset({'HOME', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'DOTENV_KEY', 'PATH', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TMPDIR'})
# No code-loading overrides are admitted, even if they would only become visible
# after Node's startup. The copied closure owns all imports and load paths.
PROHIBITED = frozenset({'NODE_OPTIONS', 'NODE_PATH', 'DOTENV_KEY'})
_JS_WHITESPACE = '\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff'
_LINE = re.compile(r'''(?:^|^)\s*(?:export\s+)?([A-Za-z0-9_.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)''', re.MULTILINE)
_LINE = re.compile(_LINE.pattern.replace(r'\s', '[' + _JS_WHITESPACE + ']'), re.MULTILINE)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parse_dotenv(data):
    if type(data) is not bytes or len(data) > 65536:
        raise OwnerError()
    try:
        lines = data.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n')
        result = {}
        for match in _LINE.finditer(lines):
            value = (match[2] or '').strip(_JS_WHITESPACE)
            quoted = value[:1]
            if len(value) >= 2 and quoted in ('"', "'", '`') and value[-1:] == quoted:
                value = value[1:-1]
            if quoted == '"':
                value = value.replace('\\n', '\n').replace('\\r', '\r')
            result[match[1]] = value
        return result
    except Exception:
        raise OwnerError() from None


def dotenv_snapshot(cwd):
    """No-follow bounded read; an absent .env is an explicit bound input."""
    path = Path(cwd) / '.env'
    try:
        path.lstat()
    except FileNotFoundError:
        return dict(present=False), {}
    data = protected_read(path, 65536, error_code='MYSQL_DOTENV_INVALID')
    # The raw bytes are never returned or persisted; HMAC provenance binds this
    # digest together with effective credentials under a secret runtime key.
    return dict(present=True, sha256=hashlib.sha256(data).hexdigest()), parse_dotenv(data)


def npm_metadata(cwd):
    """npm's local prefix is the first ancestor with package.json/node_modules.

    Only canonical versions are admitted. Unsupported npm metadata is rejected
    rather than silently substituting the MCP package's version.
    """
    directory = Path(cwd)
    if not directory.is_absolute(): raise OwnerError()
    for parent in (directory, *directory.parents):
        package = parent / 'package.json'
        if package.exists():
            try:
                metadata = json.loads(protected_read(package, 1048576, error_code='MYSQL_NPM_METADATA_INVALID'))
            except (json.JSONDecodeError, UnicodeError):
                return {}
            if type(metadata) is not dict or 'version' not in metadata: return {}
            version = metadata['version']
            if not isinstance(version, str) or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', version):
                raise OwnerError()
            return {'npm_package_version': version}
        if (parent / 'node_modules').exists(): return {}
    return {}


def effective_environment(source, inherited, cwd, *, snapshot_reader=dotenv_snapshot, metadata_reader=npm_metadata):
    try:
        if type(source) is not dict or type(source.get('env')) is not dict or type(inherited) is not dict:
            raise OwnerError()
        if any(key in PROHIBITED or key.startswith('DYLD_') for key in inherited):
            raise OwnerError()
        if any(key not in INHERITED for key in inherited):
            raise OwnerError()
        explicit = source['env']
        if any(key not in MYSQL_KEYS for key in explicit):
            raise OwnerError()
        fingerprint, parsed = snapshot_reader(cwd)
        if any(key in PROHIBITED or key.startswith('DYLD_') for key in parsed):
            raise OwnerError()
        # dotenv's override default is false: source overrides owner; all existing
        # environment values (including empty strings) override file values.
        env = {key: value for key, value in parsed.items() if key in INHERITED}
        env.update(inherited)
        env.update(explicit)
        env.update(metadata_reader(cwd))
        if any(not isinstance(value, str) or '\0' in value or len(value.encode()) > 16384 for value in env.values()):
            raise OwnerError()
        if env.get('IS_REMOTE_MCP') == 'true':
            raise OwnerError()
        return env, fingerprint
    except Exception:
        raise OwnerError() from None


class MysqlOwnerEnvironmentGuard:
    """Signed owner identity/cwd and exact source/env/.env match on every issue.

    OwnerWatch verifies the executable signature first. Construction and checking
    perform no process launch and do not copy any credential to disk.
    """
    def __init__(self, sources, expected_envs=None, expected_dotenv=None, *, identity, reader, snapshot_reader=dotenv_snapshot, metadata_reader=npm_metadata):
        try:
            dynamic = expected_envs is None and expected_dotenv is None
            if not sources or (not dynamic and (set(sources) != set(expected_envs) or set(sources) != set(expected_dotenv))) or any(not re.fullmatch('mysql-[a-z0-9-]+', backend) for backend in sources):
                raise OwnerError()
            self.dynamicContext = dynamic
            self.backends = frozenset(sources)
            self._sources = deepcopy(sources)
            self._key = os.urandom(32)
            self._expected = {} if dynamic else {backend: hmac.digest(self._key, canonical([expected_envs[backend], expected_dotenv[backend]]), 'sha256') for backend in sources}
            self._identity, self._reader, self._snapshot_reader, self._metadata_reader = identity, reader, snapshot_reader, metadata_reader
        except Exception:
            raise OwnerError() from None

    def __repr__(self):
        return '<MysqlOwnerEnvironmentGuard values withheld>'

    def __call__(self, backend, owner, client_cwd):
        try:
            if type(client_cwd) is not CwdBinding or backend not in self.backends or type(owner) is not Identity or owner.uid != os.getuid() or not (owner.path == REVIEWED_CODEX or claude_path(owner.path)):
                raise OwnerError()
            before, cwd = self._identity.process(owner.pid), self._identity.cwd(owner.pid)
            if before != owner or type(cwd) is not CwdBinding:
                raise OwnerError()
            observed, environment = self._reader.read(owner.pid, INHERITED)
            if observed != owner or self._identity.process(owner.pid) != owner or self._identity.cwd(owner.pid) != cwd:
                raise OwnerError()
            source = self._sources[backend]
            inherited = environment.environment
            env, dotenv = effective_environment(source, inherited, source.get('cwd', client_cwd.path), snapshot_reader=self._snapshot_reader, metadata_reader=self._metadata_reader)
            if self.dynamicContext:
                return {'environment': env}
            if not hmac.compare_digest(self._expected[backend], hmac.digest(self._key, canonical([env, dotenv]), 'sha256')):
                raise OwnerError()
        except Exception:
            raise OwnerError() from None
