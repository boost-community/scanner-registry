#!/bin/bash

while IFS= read -r line; do
    if [ "$(find . -name "$line" | wc -l)" != "0" ]
    then
        exit 0
    fi
done < $SETUP_PATH/../../registry/scanners/boostsecurityio/osv-scanner/filelist.txt
>&2 echo "Scan misconfiguration:"
>&2 echo "  OSV-Scanner scan did not run because no supported files were detected"
>&2 echo "  See documentation list of supported file types: https://google.github.io/osv-scanner/supported-languages-and-lockfiles/"

exit 1