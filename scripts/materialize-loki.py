#!/usr/bin/env python3
"""Offline exact Node/npm closure. No resolver, lifecycle hooks or Node execution."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('_loki_dependencies', Path(__file__).with_name('verify-loki-dependencies.py'))
dependencies = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dependencies)
integrity = dependencies.integrity
REVIEWED_NODE_WHICH_SHA256 = '055f0ac4eed1a1591d033d59462972968bf3483b4cc07e163589569c0fb999f0'
REVIEWED_DECLARATIONS = {
    '@modelcontextprotocol/sdk/dist/cjs/examples/server/mcpServerOutputSchema.d.ts': 'ba52ca94c5d34121c7e7d10e5da365140deeb89a2b1874d3ecdfc325a3849b98',
    '@modelcontextprotocol/sdk/dist/cjs/examples/client/simpleClientCredentials.d.ts': '78fc277ec93dfd9863c8a8ba400d41d7fadd741182fd47e4e7dd2b240b713e1a',
    '@modelcontextprotocol/sdk/dist/cjs/examples/client/simpleOAuthClient.d.ts': '42a781cd65d6fb5c9bdef3b403b291a5a149fca83ae161bb6246c6e25b498dc2',
    '@modelcontextprotocol/sdk/dist/esm/examples/server/mcpServerOutputSchema.d.ts': 'ba52ca94c5d34121c7e7d10e5da365140deeb89a2b1874d3ecdfc325a3849b98',
    '@modelcontextprotocol/sdk/dist/esm/examples/client/simpleClientCredentials.d.ts': '78fc277ec93dfd9863c8a8ba400d41d7fadd741182fd47e4e7dd2b240b713e1a',
    '@modelcontextprotocol/sdk/dist/esm/examples/client/simpleOAuthClient.d.ts': '42a781cd65d6fb5c9bdef3b403b291a5a149fca83ae161bb6246c6e25b498dc2',
}
SYSTEM_LOADS = (
    '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation',
    '/System/Library/Frameworks/Security.framework/Versions/A/Security',
    '/usr/lib/libSystem.B.dylib', '/usr/lib/libc++.1.dylib')


def credential_name(name):
    return name.startswith('.env') or name in ('.npmrc', 'logcli-config.yaml', '.logcli-config.yaml')


def tree_pin(root):
    return integrity.inventory_tree(root, 'app/node_modules', reject_name=credential_name)[0]


def inventory(package_root, node, *, expected_tree, expected_packages, expected_node_sha256, macho=integrity.inspect_macho):
    try:
        app = integrity.root_directory(package_root)
        node = Path(node)
        runtime = integrity.root_directory(node.parent)
        if node.name != 'node': raise integrity.SafeError('NODE_PATH_INVALID')
        ancestor_ids = [integrity.ancestors(app), integrity.ancestors(runtime)]
        entries, origins, identities = integrity.inventory_tree(app, 'app/node_modules', reject_name=credential_name)
        if entries != expected_tree: raise integrity.SafeError('PACKAGE_TREE_CHANGED')
        for entry in entries:
            if entry['kind'] != 'file': continue
            source, relative = origins[entry['path']]
            data, identity = integrity.read_file(source, relative)
            if identity != identities[entry['path']]: raise integrity.SafeError('SOURCE_CHANGED')
            if relative.name.startswith('.env') or relative.suffix in ('.node', '.dylib', '.so') or data[:4] in integrity.MAGIC or data.startswith((b'\x7fELF', b'MZ')):
                raise integrity.SafeError('PACKAGE_NATIVE_OR_SECRET_FILE')
            if entry['mode'] == 0o500 or data.startswith(b'#!'):
                reviewed_which = relative.as_posix() == 'which/bin/node-which' and entry['sha256'] == REVIEWED_NODE_WHICH_SHA256 and data.splitlines()[0] == b'#!/usr/bin/env node'
                reviewed_declaration = entry['mode'] == 0o400 and REVIEWED_DECLARATIONS.get(relative.as_posix()) == entry['sha256'] and data.splitlines()[0] == b'#!/usr/bin/env node'
                if (relative.suffix not in ('.js', '.mjs', '.cjs') and not reviewed_which and not reviewed_declaration) or (data.startswith(b'#!') and data.splitlines()[0] not in (b'#!/usr/bin/env node', b'#!/usr/bin/node')):
                    raise integrity.SafeError('PACKAGE_EXECUTABLE_UNREVIEWED')
        data, identity = integrity.read_file(runtime, Path('node'))
        if integrity.hashlib.sha256(data).hexdigest() != expected_node_sha256 or data[:4] not in integrity.MAGIC or not identity[2] & 0o111:
            raise integrity.SafeError('NODE_PIN_CHANGED')
        native = macho(node)
        if set(native) != {'architectures', 'loads', 'rpaths', 'installIds'} or native['architectures'] != ['arm64'] or native['rpaths'] or sorted(native['loads']) != sorted(SYSTEM_LOADS):
            raise integrity.SafeError('NODE_LOAD_EDGES_CHANGED')
        report = dependencies.report(app, expected_packages=expected_packages)
        files = {entry['path']: entry for entry in entries if entry['kind'] == 'file'}
        for path, package in report['packages'].items():
            if package['metadataSha256'] != files['app/node_modules/'+path+'/package.json']['sha256']:
                raise integrity.SafeError('DEPENDENCY_METADATA_CHANGED')
        report_digest = integrity.hashlib.sha256(integrity.canonical(report)).hexdigest()
        entries += [dict(path=name, kind='directory', mode=0o500) for name in ('app','runtime','runtime/bin')]
        entries.append(dict(path='runtime/bin/node', kind='file', mode=0o500, size=len(data), sha256=expected_node_sha256))
        origins['runtime/bin/node'] = (runtime, Path('node')); identities['runtime/bin/node'] = identity
        document = dict(version=1, runtime='node', entries=sorted(entries,key=lambda entry:entry['path']),
            native={'runtime/bin/node':native}, systemDependencies=sorted(SYSTEM_LOADS), dependencyReport=report, dependencyReportDigest=report_digest)
        options = dict(expected_tree=expected_tree, expected_packages=expected_packages, expected_node_sha256=expected_node_sha256, macho=macho)
        snapshot = integrity.Snapshot(document, origins, identities, options, app, runtime)
        # Pin both roots' ancestor identities through the complete scan.
        for ancestors in ancestor_ids: integrity.check_ancestors(ancestors)
        return snapshot
    except (OSError, ValueError, RuntimeError, UnicodeError, KeyError, TypeError) as error:
        raise integrity.SafeError('LOKI_INVENTORY_INVALID') from error


def unchanged(snapshot):
    current = inventory(snapshot.app, snapshot.python/'node', **snapshot.options)
    if current.document != snapshot.document or current.identities != snapshot.identities:
        raise integrity.SafeError('SOURCE_CHANGED')


def materialize(snapshot, parent):
    return integrity.materialize(snapshot, parent, recheck=unchanged)
