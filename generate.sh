#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

# The supported package consumes these fields, rather than the strict reference transport.
python3 scripts/generate_wire.py

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. Start Docker and run this script again." >&2
  exit 1
fi

generator="python"
image="openapitools/openapi-generator-cli:v7.23.0"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

python3 - "$PWD/resources/shieldlabs-api.yaml" "$workdir/spec.yaml" << 'PY'
import sys
from pathlib import Path

source, dest = sys.argv[1:]
lines = Path(source).read_text().splitlines(keepends=True)
out = []
i = 0
while i < len(lines):
    if lines[i].startswith("  description:"):
        out.append("  description: Identification results and risk scoring for your backend.\n")
        i += 1
        while i < len(lines) and not (lines[i].startswith("  ") and not lines[i].startswith("   ")):
            i += 1
        continue
    out.append(lines[i])
    i += 1
Path(dest).write_text("".join(out))
PY

rm -rf generated
mkdir -p generated
cat > generated/.openapi-generator-ignore << 'IGN'
README.md
git_push.sh
.travis.yml
.gitignore
docs/
test/
api/openapi.yaml
.github/
IGN

docker run --rm -u "$(id -u):$(id -g)" \
  -v "$PWD":/local -v "$workdir":/work -w /local \
  "$image" generate \
  -i /work/spec.yaml \
  -g "$generator" \
  -o /local/generated \
  -c /local/config.json \
  --global-property apis,models,supportingFiles,modelTests=false,apiTests=false,modelDocs=false,apiDocs=false

find generated \( -name README.md -o -name '*README.md' -o -name git_push.sh -o -name .travis.yml -o -name appveyor.yml -o -name .gitignore -o -name build.sbt -o -name '*.sln' \) -delete
rm -rf generated/docs generated/test generated/.github
find generated -type d -empty -delete

if [ "$generator" = "go" ]; then
  docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/generated":/src -w /src golang:1.24-bookworm gofmt -w .
  cat > generated/go.mod << 'MOD'
module github.com/ShieldLabs-ai/shieldlabs-go/generated

go 1.23
MOD
fi
