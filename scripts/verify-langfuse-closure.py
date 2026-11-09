#!/usr/bin/env python3
"""Isolated host-only tree check; never executes or imports the copied closure."""
import importlib.util
import json
from pathlib import Path
import re
import sys


def main(argv):
    try:
        if len(argv) != 4 or argv[0] != '--root' or argv[2] != '--digest':
            raise ValueError('arguments')
        root, digest = Path(argv[1]), argv[3]
        if not root.is_absolute() or root.name != digest or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('closure')
        # -I -S excludes user cwd/site hooks. Only manager-owned sibling modules
        # are explicitly admitted; no artifact paths are added to sys.path.
        scripts = Path(__file__).resolve().parent
        sys.path.insert(0, str(scripts))
        spec = importlib.util.spec_from_file_location('_manager_closure_integrity', scripts/'materialize-langfuse.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        module.verify(root, expected_digest=digest)
    except Exception:
        print('{"code":"CLOSURE_INVALID"}')
        return 1
    print(json.dumps(dict(version=1, valid=True, digest=digest), separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
