#!/usr/bin/env python3
"""Static, bounded npm metadata resolution; never executes package code."""
import importlib.util
import json
from pathlib import Path
import re
import sys

spec = importlib.util.spec_from_file_location('_loki_integrity', Path(__file__).with_name('materialize-langfuse.py'))
integrity = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = integrity
spec.loader.exec_module(integrity)


def numeric(value):
    if not re.fullmatch(r'(0|[1-9]\d*)(\.(0|[1-9]\d*)){0,2}', value):
        raise ValueError('VERSION_GRAMMAR_UNREVIEWED')
    parts = tuple(map(int, value.split('.')))
    return parts + (0,) * (3-len(parts)), len(parts)


def satisfies(version, expression):
    current, length = numeric(version)
    if length != 3 or not isinstance(expression, str): raise ValueError('VERSION_INVALID')
    accepted = False
    for alternative in expression.split('||'):
        tokens = re.findall(r'(\^|~|>=|<=|>|<|=)?\s*((?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){0,2})', alternative)
        remainder = re.sub(r'(\^|~|>=|<=|>|<|=)?\s*((?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){0,2})', '', alternative)
        if remainder.strip() or not tokens: raise ValueError('RANGE_GRAMMAR_UNREVIEWED')
        matches = True
        for operator, operand in tokens:
            lower, count = numeric(operand)
            if operator in ('>', '<', '<=', '=') and count != 3:
                raise ValueError('PARTIAL_COMPARATOR_UNREVIEWED')
            if operator in ('^', '~') or (not operator and count < 3):
                if operator == '^':
                    index = next((i for i, number in enumerate(lower) if number), count-1)
                else: index = 0 if count == 1 else 1
                upper = lower[:index] + (lower[index]+1,) + (0,)*(2-index)
                matches &= lower <= current < upper
            elif operator in ('', '='): matches &= current == lower
            elif operator == '>=': matches &= current >= lower
            elif operator == '<=': matches &= current <= lower
            elif operator == '>': matches &= current > lower
            elif operator == '<': matches &= current < lower
        accepted |= matches
    return accepted


def package_paths(root):
    """Package roots only, excluding examples/test fixture package.json files."""
    result = []
    def visit(modules):
        for child in sorted(modules.iterdir()):
            if child.name.startswith('.'): continue
            if child.is_symlink(): raise ValueError('PACKAGE_LINK_UNREVIEWED')
            candidates = sorted(child.iterdir()) if child.name.startswith('@') and child.is_dir() else [child]
            for package in candidates:
                if package.is_symlink(): raise ValueError('PACKAGE_LINK_UNREVIEWED')
                if not package.is_dir() or not (package/'package.json').is_file(): raise ValueError('PACKAGE_METADATA_MISSING')
                result.append(package.relative_to(root).as_posix())
                nested = package/'node_modules'
                if nested.is_symlink(): raise ValueError('PACKAGE_LINK_UNREVIEWED')
                if nested.exists(): visit(nested)
    visit(root)
    return result


def report(root, *, expected_packages=None):
    root = integrity.root_directory(root)
    packages = {}
    for path in package_paths(root):
        data, _ = integrity.read_file(root, Path(path)/'package.json')
        meta = json.loads(data)
        name, version = meta.get('name'), meta.get('version')
        if not isinstance(name, str) or not re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9._-]+', name): raise ValueError('PACKAGE_IDENTITY_INVALID')
        if numeric(version)[1] != 3: raise ValueError('PACKAGE_VERSION_INVALID')
        if path.split('/node_modules/')[-1] != name: raise ValueError('PACKAGE_IDENTITY_MISMATCH')
        packages[path] = dict(name=name, version=version, metadataSha256=integrity.hashlib.sha256(data).hexdigest(), dependencies=[], _metadata=meta)
    identities = {path: dict(name=record['name'], version=record['version']) for path, record in packages.items()}
    if expected_packages is not None and identities != expected_packages: raise ValueError('PACKAGE_PINS_CHANGED')
    for path, record in packages.items():
        meta = record.pop('_metadata')
        mandatory = meta.get('dependencies', {})
        optional = meta.get('optionalDependencies', {})
        peers = meta.get('peerDependencies', {})
        peer_meta = meta.get('peerDependenciesMeta', {})
        for kind, declared in [('mandatory', mandatory), ('peer', peers), ('optional', optional)]:
            if not isinstance(declared, dict): raise ValueError('DEPENDENCIES_INVALID')
            for name, requested in sorted(declared.items()):
                if kind == 'mandatory' and name in optional: continue
                if not re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9._-]+', name): raise ValueError('DEPENDENCY_NAME_INVALID')
                # Validate grammar even for an intentionally absent optional edge.
                satisfies('0.0.0', requested)
                candidate = Path(path)
                resolved = None
                while True:
                    location = (candidate/'node_modules'/name).as_posix()
                    if location in packages: resolved = location; break
                    if candidate == Path('.'): break
                    candidate = candidate.parent
                if resolved is None and name in packages: resolved = name
                absent_allowed = kind == 'optional' or (kind == 'peer' and peer_meta.get(name, {}).get('optional') is True)
                if resolved is None and not absent_allowed: raise ValueError('DEPENDENCY_MISSING')
                if resolved is not None and not satisfies(packages[resolved]['version'], requested): raise ValueError('DEPENDENCY_VERSION_MISMATCH')
                record['dependencies'].append(dict(name=name, kind=kind, requested=requested, resolvedPath=resolved,
                    resolvedVersion=packages[resolved]['version'] if resolved else None, outcome='resolved' if resolved else 'absent-optional'))
    return dict(version=1, validation='static-reviewed-semver-no-execution', packages=packages)
