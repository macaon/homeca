#!/bin/sh
# Build this app's image, then push it as :latest - but only if it actually changed. Before
# overwriting a *different* image at :latest, demote the current one to a tag named after its
# own build date (read from the image config, not wall-clock time), so it stays pullable for
# rollback. Rebuilding unchanged source is a no-op: nothing is demoted or pushed.
set -e
cd "$(dirname "$0")"
name=$(basename "$(pwd)")
img="docker.home.arpa/$name"
api="https://docker.home.arpa/v2/$name"
accept="application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json"

podman build -t "$img:latest" -f Containerfile .
local_id=$(podman image inspect --format '{{.Id}}' "$img:latest")

manifest=$(curl -fsS -H "Accept: $accept" "$api/manifests/latest") || manifest=""
if [ -n "$manifest" ]; then
  config_digest=$(printf '%s' "$manifest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["config"]["digest"])') || config_digest=""
  if [ -n "$config_digest" ] && [ "${config_digest#sha256:}" = "$local_id" ]; then
    echo "$name: no change since current :latest, nothing to push"
    exit 0
  fi
  if [ -n "$config_digest" ]; then
    media_type=$(printf '%s' "$manifest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["mediaType"])')
    created=$(curl -fsS "$api/blobs/$config_digest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["created"])')
    ts=$(python3 -c 'import datetime,sys; print(datetime.datetime.fromisoformat(sys.argv[1]).astimezone(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S"))' "$created")
    echo "demoting current $name:latest -> :$ts"
    curl -fsS -X PUT -H "Content-Type: $media_type" --data-binary "$manifest" "$api/manifests/$ts" >/dev/null
  fi
  # ponytail: multi-arch manifest lists have no top-level "config" - demotion silently no-ops
  # for those (falls through to a plain push), since this family doesn't build multi-arch
  # images today.
fi

podman push "$img:latest"
echo "pushed $img:latest"
