#!/bin/sh
set -e

CUCKOODIR="../cuckoo"
MONITOR="monitor.dll"

case "$#" in
    1)
        CUCKOODIR="$1"
        ;;

    2)

        CUCKOODIR="$1"
        MONITOR="$2"
        ;;
esac

make
cp monitor.dll "$CUCKOODIR/analyzer/windows/dll/$MONITOR"
