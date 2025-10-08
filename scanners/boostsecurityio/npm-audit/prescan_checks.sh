#!/bin/bash

if [ "$(ls | grep "package-lock.json" | wc -l)" != "0" ]
then
    exit 0
fi

>&2 echo "Scan misconfiguration: NPM audit require a package-lock.json file which is missing."
exit 1 