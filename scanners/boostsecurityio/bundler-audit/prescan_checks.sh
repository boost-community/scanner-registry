#!/bin/bash

GEMFILE_LOCK=${GEMFILE_LOCK:-Gemfile.lock}
if [ "$(ls | grep "$GEMFILE_LOCK" | wc -l)" != "0" ]
then
    exit 0
fi

>&2 echo "Scan misconfiguration: Bundler audit require a $GEMFILE_LOCK file which is missing."
exit 1 