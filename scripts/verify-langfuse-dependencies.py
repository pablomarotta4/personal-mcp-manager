#!/usr/bin/env python3
"""Offline installed-dependency check. Imports only verified copied packaging26.3.

No resolver, installation, source environment, auxiliary pip, SDK or application
imports. Evaluate base requirements of every installed distribution, plus extras
requested by langfuse-mcp and mcp[cli]<2, including transitive extra requests.
"""
import argparse
from collections import deque
from email.parser import BytesParser
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOTS = ('langfuse-mcp', 'mcp[cli]<2')


class DependencyError(Exception):
    def __init__(self, code, **details):
        super().__init__(code)
        self.details = details  # Canonical package names only; never raw requirements/URLs.


def integrity_module():
    scripts = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('langfuse_dependency_integrity', scripts/'materialize-langfuse.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    previous = sys.path[:]
    try:
        sys.path.insert(0, str(scripts))
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = previous
    return module


def packaging_origins(artifact, document, integrity):
    admitted = {entry['path']: entry for entry in document['entries'] if entry['kind'] == 'file'}
    count = 0
    for name, module in list(sys.modules.items()):
        if name != 'packaging' and not name.startswith('packaging.'): continue
        path = Path(getattr(module, '__file__', '')).resolve(strict=True)
        prefix = artifact/'app/site-packages/packaging'
        if not path.is_relative_to(prefix): raise DependencyError('PACKAGING_ORIGIN_INVALID')
        relative = path.relative_to(artifact)
        entry = admitted.get(relative.as_posix())
        if not entry: raise DependencyError('PACKAGING_ORIGIN_INVALID')
        data, _ = integrity.read_file(artifact, relative)
        if hashlib.sha256(data).hexdigest() != entry['sha256'] or len(data) != entry['size']:
            raise DependencyError('PACKAGING_BYTES_CHANGED')
        if Path(module.__spec__.origin).resolve(strict=True) != path:
            raise DependencyError('PACKAGING_ORIGIN_INVALID')
        count += 1
    return count


def load_packaging(artifact, expected_digest):
    artifact = Path(artifact)
    if not re.fullmatch('[0-9a-f]{64}', expected_digest): raise DependencyError('DIGEST_INVALID')
    integrity = integrity_module()
    document = integrity.verify(artifact, expected_digest=expected_digest)
    if document['distributions'].get('packaging') != '26.3': raise DependencyError('PACKAGING_VERSION_MISMATCH')
    prefix = artifact/'app/site-packages/packaging'
    for name, module in list(sys.modules.items()):
        if name == 'packaging' or name.startswith('packaging.'):
            if not Path(getattr(module, '__file__', '')).resolve().is_relative_to(prefix):
                raise DependencyError('PACKAGING_ALREADY_LOADED')
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        if 'packaging' not in sys.modules:
            spec = importlib.util.spec_from_file_location('packaging', prefix/'__init__.py', submodule_search_locations=[str(prefix)])
            module = importlib.util.module_from_spec(spec)
            sys.modules['packaging'] = module
            spec.loader.exec_module(module)
        modules = {name: importlib.import_module('packaging.'+name) for name in ('requirements', 'specifiers', 'version', 'utils', 'markers')}
    finally:
        sys.dont_write_bytecode = previous
    packaging_origins(artifact, document, integrity)
    return modules


def validate_metadata(raw_metadata, roots, expected, environment, packaging):
    Requirement = packaging['requirements'].Requirement
    SpecifierSet = packaging['specifiers'].SpecifierSet
    Version = packaging['version'].Version
    canonicalize = packaging['utils'].canonicalize_name
    records, versions = {}, {}
    requires_python = 0
    for raw in raw_metadata:
        meta = BytesParser().parsebytes(raw, headersonly=True)
        try:
            if len(meta.get_all('Name', [])) != 1 or len(meta.get_all('Version', [])) != 1 or len(meta.get_all('Requires-Python', [])) > 1:
                raise DependencyError('METADATA_INVALID')
            name = canonicalize(meta['Name'], validate=True)
            if name in records: raise DependencyError('METADATA_DUPLICATE', package=name)
            version = Version(meta['Version'])
            provided = {canonicalize(extra, validate=True) for extra in meta.get_all('Provides-Extra', [])}
            requirements = []
            for value in meta.get_all('Requires-Dist', []):
                try: requirement = Requirement(value)
                except ValueError as error: raise DependencyError('REQUIREMENT_INVALID', package=name) from error
                if requirement.url: raise DependencyError('DIRECT_URL_UNSUPPORTED', package=name)
                requirements.append(requirement)
            python = meta.get('Requires-Python')
            if python:
                requires_python += 1
                if not SpecifierSet(python).contains(environment['python_full_version'], prereleases=True):
                    raise DependencyError('PYTHON_VERSION_MISMATCH', package=name)
        except (ValueError, KeyError, TypeError) as error:
            raise DependencyError('METADATA_INVALID') from error
        records[name] = (version, provided, requirements)
        versions[name] = meta['Version']
    if versions != expected: raise DependencyError('INVENTORY_MISMATCH')
    if len(records) > 128 or sum(len(record[2]) for record in records.values()) > 4096: raise DependencyError('METADATA_LIMIT')
    extras = {name: set() for name in records}
    queue = deque(sorted(records))

    def admit(requirement, owner):
        name = canonicalize(requirement.name)
        if name not in records: raise DependencyError('MISSING_DEPENDENCY', package=owner, dependency=name)
        version, provided, _ = records[name]
        if not requirement.specifier.contains(version, prereleases=True):
            raise DependencyError('DEPENDENCY_VERSION_MISMATCH', package=owner, dependency=name)
        requested = {canonicalize(extra) for extra in requirement.extras}
        if requested - provided: raise DependencyError('UNKNOWN_EXTRA', package=owner, dependency=name)
        previous = len(extras[name])
        extras[name].update(requested)
        if len(extras[name]) != previous: queue.append(name)

    for value in roots:
        try: requirement = Requirement(value)
        except ValueError as error: raise DependencyError('ROOT_INVALID') from error
        if requirement.url: raise DependencyError('DIRECT_URL_UNSUPPORTED')
        if requirement.marker is not None: raise DependencyError('ROOT_MARKER_UNSUPPORTED')
        admit(requirement, None)
    processed, active, inactive = {}, set(), set()
    while queue:
        owner = queue.popleft()
        current = frozenset(extras[owner])
        if processed.get(owner) == current: continue
        processed[owner] = current
        for index, requirement in enumerate(records[owner][2]):
            edge = (owner, index)
            try:
                enabled = requirement.marker is None or any(requirement.marker.evaluate({**environment, 'extra': extra}, context='metadata') for extra in ('', *sorted(current)))
            except (ValueError, LookupError) as error:
                raise DependencyError('MARKER_INVALID', package=owner) from error
            if enabled:
                active.add(edge)
                inactive.discard(edge)
                admit(requirement, owner)
            elif edge not in active: inactive.add(edge)
    return {'distributionCount': len(records), 'requiresPythonChecked': requires_python,
            'activeRequirements': len(active), 'inactiveRequirements': len(inactive),
            'requestedExtras': {name: sorted(values) for name, values in sorted(extras.items()) if values},
            'exactInventory': True}


def validate_artifact(artifact, expected_digest):
    artifact = Path(artifact)
    if Path(sys.executable).resolve(strict=True) != artifact/'python/bin/python3.13' or sys.version_info[:3] != (3, 13, 12):
        raise DependencyError('COPIED_PYTHON_REQUIRED')
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode): raise DependencyError('ISOLATED_FLAGS_REQUIRED')
    if any(Path(path).name == 'site-packages' for path in sys.path): raise DependencyError('SITE_PACKAGES_PRESENT')
    integrity = integrity_module()
    document = integrity.verify(artifact, expected_digest=expected_digest)
    packaging = load_packaging(artifact, expected_digest)
    environment = packaging['markers'].default_environment()
    metadata = [integrity.read_file(artifact, Path(entry['path']))[0] for entry in document['entries']
                if entry['kind'] == 'file' and entry['path'].startswith('app/site-packages/') and entry['path'].endswith('.dist-info/METADATA')]
    result = validate_metadata(metadata, ROOTS, integrity.DISTRIBUTIONS, environment, packaging)
    modules = packaging_origins(artifact, document, integrity)
    if any(name in ('langfuse', 'langfuse_mcp', 'pip') or name.startswith(('langfuse.', 'langfuse_mcp.', 'pip.')) for name in sys.modules):
        raise DependencyError('UNAPPROVED_MODULE_IMPORTED')
    return {'version': 1, 'verdict': 'PASS', 'artifactDigest': expected_digest, 'roots': list(ROOTS), **result,
            'environment': {key: environment[key] for key in ('implementation_name', 'python_version', 'python_full_version', 'sys_platform', 'platform_system', 'platform_machine', 'os_name')},
            'packagingVersion': '26.3', 'verifiedPackagingModules': modules, 'runtimePipExcluded': True,
            'applicationImported': False, 'networkUsed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', required=True, type=Path)
    parser.add_argument('--expected-digest', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(validate_artifact(args.artifact, args.expected_digest), sort_keys=True))
    except DependencyError as error:
        print(json.dumps({'verdict': 'FAIL', 'code': str(error), **error.details}, sort_keys=True))
        return 1
    except Exception:
        # Outermost CLI isolation: fail closed without tracebacks/raw metadata.
        print(json.dumps({'verdict': 'FAIL', 'code': 'DEPENDENCY_VERIFICATION_FAILED'}, sort_keys=True))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
