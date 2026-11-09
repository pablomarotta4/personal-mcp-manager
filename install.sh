#!/bin/sh
set -eu
umask 077
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
python_bin=${MCP_MANAGER_PYTHON:-python3}
exec "$python_bin" "$project_dir/scripts/install.py" "$@"
