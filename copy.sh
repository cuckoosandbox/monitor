#!/bin/sh

# Copies the Cuckoo Monitor binaries to the Cuckoo CWD.
HASH=$(git rev-parse HEAD)
mkdir -p ~/.cuckoo/monitor/$HASH
cp bin/*.dll bin/*.exe ~/.cuckoo/monitor/$HASH
echo $HASH > ~/.cuckoo/monitor/latest
