#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    rm -rf /opt/eip-search
    rm -f /usr/local/bin/eip-search
fi

exit 0
