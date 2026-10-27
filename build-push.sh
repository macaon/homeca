#!/bin/sh
# Build and push this app's image. :latest always names the single newest build - before
# overwriting it, demote whatever is CURRENTLY tagged :latest (if anything) to a tag named
# after its own build date, so a rollback target survives without ever double-tagging the
# build being pushed right now.
set -e
cd "$(dirname "$0")"
name=$(basename "$(pwd)")
img="docker.home.arpa/$name"
api="https://docker.home.arpa/v2/$name"
accept="application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json"

demote_current_latest() {
  manifest=$(curl -fsS -H "Accept: $accept" "$api/manifests/latest") || return 0
  media_type=$(printf '%s' "$manifest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["mediaType"])') || return 0
  config_digest=$(printf '%s' "$manifest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["config"]["digest"])') || return 0
  created=$(curl -fsS "$api/blobs/$config_digest" | python3 -c 'import json,sys; print(json.load(sys.stdin)["created"])') || return 0
  ts=$(python3 -c 'import datetime,sys; print(datetime.datetime.fromisoformat(sys.argv[1]).astimezone(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S"))' "$created")
  echo "demoting current $name:latest -> :$ts"
  curl -fsS -X PUT -H "Content-Type: $media_type" --data-binary "$manifest" "$api/manifests/$ts" >/dev/null
}
# ponytail: multi-arch manifest lists have no top-level "config" - demotion silently no-ops for
# those (falls through to a plain push), since this family doesn't build multi-arch images today.

demote_current_latest
podman build -t "$img:latest" -f Containerfile .
podman push "$img:latest"
echo "pushed $img:latest"
