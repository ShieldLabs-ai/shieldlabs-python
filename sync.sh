#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

schemaUrl="${1:-https://raw.githubusercontent.com/ShieldLabs-ai/shieldlabs-openapi/main/dist/shieldlabs-api.yaml}"
schemaDestination="./resources/shieldlabs-api.yaml"

mkdir -p "$(dirname "$schemaDestination")"

echo "Downloading $schemaUrl to $schemaDestination"
curl -fSL --retry 3 --proto-redir '=https' --connect-timeout 10 --max-time 120 \
  -o "$schemaDestination" "$schemaUrl"

echo "OpenAPI schema download complete. Run ./generate.sh to refresh generated/."
