#!/bin/sh
# Build and push this app's image, tagged :latest and :<UTC timestamp> - so :latest is always traceable to
# when it was built, and old builds stay pullable under their timestamp tag for rollback.
set -e
cd "$(dirname "$0")"
name=$(basename "$(pwd)")
ts=$(date -u +%Y%m%d-%H%M%S)
img="docker.home.arpa/$name"

podman build -t "$img:$ts" -t "$img:latest" -f Containerfile .
podman push "$img:$ts"
podman push "$img:latest"
echo "pushed $img:$ts and $img:latest"
