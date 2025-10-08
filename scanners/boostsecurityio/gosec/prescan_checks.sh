#!/bin/bash

if [ "$(find . -name "*.go" | wc -l)" != "0" ]
then
    exit 0
fi
>&2 echo "Scan misconfiguration: Gosec only work for repositories with go code."
exit 1 