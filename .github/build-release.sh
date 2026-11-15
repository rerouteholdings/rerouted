#!/bin/sh
# build-release.sh DIR: the release binaries, built reproducibly into DIR, with SHA256SUMS.
# The same commit, Go version, and flags give the same bytes: no cgo, no local paths
# (-trimpath), no build ID, and the version from the tag (or "dev").
set -eu
out=$1
version=${GITHUB_REF_NAME:-dev}
version=${version#v}
mkdir -p "$out"
for arch in amd64 arm64; do
	for cmd in rerouted rerouted-keyd rerouted-sfu; do
		CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -buildvcs=false \
			-ldflags "-buildid= -X github.com/rerouteholdings/rerouted/internal/version.Number=$version" \
			-o "$out/$cmd-linux-$arch" "./cmd/$cmd"
	done
done
cd "$out" && sha256sum rerouted* > SHA256SUMS && cat SHA256SUMS
