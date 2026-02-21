#!/bin/sh
set -e

# On remove or purge, clean up anything dpkg didn't track
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    rm -rf /opt/eip-search
fi

exit 0
