#!/bin/sh
set -e

# On upgrade, remove the old venv so it's cleanly replaced
if [ "$1" = "upgrade" ] || [ "$1" = "install" ]; then
    rm -rf /opt/eip-search
fi

exit 0
