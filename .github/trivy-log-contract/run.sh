#!/usr/bin/env bash
# Run the canary once per distinct trivy pin of the modules scanning pom.xml.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
MODULES=$HERE/../../scanners/boostsecurityio
IMAGE=public.ecr.aws/docker/library/python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285

for module in boost-sca trivy-fs trivy-sbom; do
  yq -e -o=json -I=0 '.setup[] | select(.name == "download trivy") | .environment' \
    "$MODULES/$module/module.yaml"
done | sort -u | while read -r pin; do
  docker run --rm --add-host repo.maven.apache.org:127.0.0.1 \
    -e TRIVY_PIN="$pin" -v "$HERE:/canary:ro" "$IMAGE" python3 /canary/canary.py
done
