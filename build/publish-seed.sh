#!/usr/bin/env bash
# Build the two seed databases as images and push them to GitHub Container
# Registry, tagged with the seed's date and latest:
#
#   ghcr.io/titeee/heretix-demo-api-db
#   ghcr.io/titeee/heretix-demo-management-db
#
#   build/publish-seed.sh <YYYY.MM.DD>     (after make-seed.sh; docker login ghcr.io first)
set -euo pipefail
cd "$(dirname "$0")/.."
version=${1:?usage: publish-seed.sh <YYYY.MM.DD>}
for seed in api management; do
  image=ghcr.io/titeee/heretix-demo-$seed-db
  docker buildx build --platform linux/amd64,linux/arm64 \
    -f images/seed-db.Dockerfile --build-arg SEED=$seed \
    --label org.opencontainers.image.source=https://github.com/TITeee/heretix-demo \
    --label "org.opencontainers.image.description=heretix demo: the $seed database with sample data" \
    -t $image:$version -t $image:latest --push .
done
