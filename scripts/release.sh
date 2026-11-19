#!/usr/bin/env bash
# Builds a rerouted release for Linux, amd64 and arm64, into dist/release/VERSION/:
#
#   rerouted-VERSION-linux-ARCH.tar.gz   the binary, LICENSE, README.md, the settings example,
#                                        the man page, completions, and systemd units for a
#                                        binary in /usr/local/bin
#   SHA256SUMS                           the tarballs' checksums
#   rerouted_*.deb, rerouted-*.rpm,      packages for apt, dnf, and pacman, made with nfpm
#   rerouted-*.pkg.tar.zst
#   latest.json                          {"version", "published", "notes"}, for the update check
#
#   scripts/release.sh VERSION           such as 0.2.0 or 0.2.0-rc.1
#
# It builds the committed tree (HEAD, or REF), not uncommitted changes. Nothing here is signed. The repositories that publish a release sign its packages and
# SHA256SUMS with their own key. Needs Go only; nfpm is pinned below and built with Go.
# env: REF (default HEAD), NOTES_URL (default: the GitHub release for vVERSION), SOURCE_DATE_EPOCH (default: the
#      last commit's time; file times in the packages and tarballs)
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${1:?usage: scripts/release.sh VERSION}
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$ ]] \
  || { echo "$VERSION isn't a version like 0.2.0 or 0.2.0-rc.1" >&2; exit 1; }
NFPM=github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.49.0
NOTES_URL=${NOTES_URL:-https://github.com/rerouteholdings/rerouted/releases/tag/v$VERSION}
REF=${REF:-HEAD}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct HEAD)}
[ -z "$(git status --porcelain --untracked-files=no)" ] \
  || echo "note: uncommitted changes aren't in the release; it builds $REF" >&2

OUT=$PWD/dist/release/$VERSION
STAGE=dist/release/.stage-$VERSION
rm -rf "$OUT" "$STAGE"
mkdir -p "$OUT" "$STAGE/bin" "$STAGE/src"
STAGE=$(cd "$STAGE" && pwd)
trap 'rm -rf "$STAGE"' EXIT
git archive "$REF" | tar -x -C "$STAGE/src"
cd "$STAGE/src"

echo "==> building rerouted $VERSION"
LDFLAGS="-s -w -X github.com/rerouteholdings/rerouted/internal/version.Number=$VERSION"
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o "$STAGE/rerouted-linux-$arch" ./cmd/rerouted
done
# One for this machine too, to write the shell completions.
CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$STAGE/bin/rerouted" ./cmd/rerouted
GOBIN=$STAGE/bin go install "$NFPM"

# The settings example, for a packaged install.
sed -e '1s|.*|# rerouted settings. sudo rerouted init writes /etc/rerouted/rerouted.env (or NAME.env, for rerouted@NAME), or copy this file there. Real environment variables override it.|' \
  -e 's|^REROUTED_DATA_DIR=.*|REROUTED_DATA_DIR=/var/lib/rerouted|' .env.example > "$STAGE/rerouted.env.example"
grep -q '^REROUTED_DATA_DIR=/var/lib/rerouted$' "$STAGE/rerouted.env.example" \
  || { echo ".env.example has no REROUTED_DATA_DIR line to set" >&2; exit 1; }

# The man page and completions, when this version has them.
EXTRA=()
if [ -f docs/rerouted.1 ]; then
  gzip -9n < docs/rerouted.1 > "$STAGE/rerouted.1.gz"
  EXTRA+=("$STAGE/rerouted.1.gz /usr/share/man/man1/rerouted.1.gz")
else
  echo "note: no docs/rerouted.1, so no man page" >&2
fi
# Each shell's script, if `rerouted completion SHELL` prints one. Run in an empty directory
# with no settings, so an older binary that doesn't know the command can't start a server.
complete_for() { # shell pattern
  local d; d=$(mktemp -d)
  if (cd "$d" && env -i PATH=/usr/bin:/bin "$STAGE/bin/rerouted" completion "$1") > "$STAGE/completion.$1" 2>/dev/null \
    && grep -q -- "$2" "$STAGE/completion.$1"; then
    rm -rf "$d"
    return 0
  fi
  rm -rf "$d" "$STAGE/completion.$1"
  return 1
}
mkdir -p "$STAGE/completions"
if complete_for bash 'complete '; then
  mv "$STAGE/completion.bash" "$STAGE/completions/rerouted"
  EXTRA+=("$STAGE/completions/rerouted /usr/share/bash-completion/completions/rerouted")
fi
if complete_for zsh 'compdef'; then
  mv "$STAGE/completion.zsh" "$STAGE/completions/_rerouted"
  EXTRA+=("$STAGE/completions/_rerouted /usr/share/zsh/vendor-completions/_rerouted deb")
  EXTRA+=("$STAGE/completions/_rerouted /usr/share/zsh/site-functions/_rerouted rpm")
  EXTRA+=("$STAGE/completions/_rerouted /usr/share/zsh/site-functions/_rerouted archlinux")
fi
if complete_for fish 'complete -c'; then
  mv "$STAGE/completion.fish" "$STAGE/completions/rerouted.fish"
  EXTRA+=("$STAGE/completions/rerouted.fish /usr/share/fish/vendor_completions.d/rerouted.fish")
fi
[ -n "$(ls "$STAGE/completions")" ] || echo "note: rerouted has no completion command, so no completions" >&2

# nfpm's configuration, with those files added.
cp packaging/nfpm.yaml "$STAGE/nfpm.yaml"
for e in ${EXTRA[@]+"${EXTRA[@]}"}; do
  set -- $e
  printf '  - src: %s\n    dst: %s\n    file_info: { mode: 0644 }\n' "$1" "$2" >> "$STAGE/nfpm.yaml"
  [ -n "${3:-}" ] && printf '    packager: %s\n' "$3" >> "$STAGE/nfpm.yaml"
done

# Tarballs, for installing by hand.
if tar --version 2>/dev/null | grep -q bsdtar; then
  TAR=(env COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata --uid 0 --gid 0 --uname root --gname root)
else
  TAR=(tar --owner=0 --group=0 --numeric-owner --sort=name --mtime="@$SOURCE_DATE_EPOCH")
fi
for arch in amd64 arm64; do
  name=rerouted-$VERSION-linux-$arch
  d=$STAGE/tar/$name
  mkdir -p "$d/systemd"
  install -m 755 "$STAGE/rerouted-linux-$arch" "$d/rerouted"
  install -m 644 LICENSE README.md "$STAGE/rerouted.env.example" "$d/"
  [ -f docs/rerouted.1 ] && install -m 644 docs/rerouted.1 "$d/"
  [ -n "$(ls "$STAGE/completions")" ] && cp -R "$STAGE/completions" "$d/"
  for u in rerouted.service rerouted@.service; do
    sed 's|/usr/bin/rerouted|/usr/local/bin/rerouted|g' "packaging/systemd/$u" > "$d/systemd/$u"
  done
  find "$d" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} + 2>/dev/null \
    || find "$d" -exec touch -h -t "$(date -u -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)" {} +
  "${TAR[@]}" -czf "$OUT/$name.tar.gz" -C "$STAGE/tar" "$name"
done
(cd "$OUT" && if command -v sha256sum >/dev/null; then sha256sum rerouted-*.tar.gz; else shasum -a 256 rerouted-*.tar.gz; fi) > "$OUT/SHA256SUMS"

echo "==> packages"
for arch in amd64 arm64; do
  for p in deb rpm archlinux; do
    # pacman's versions can't have a hyphen: 0.2.0-rc.1 is 0.2.0rc1 (as for Reroute), which
    # sorts before 0.2.0.
    v=$VERSION
    if [ "$p" = archlinux ] && [ "$VERSION" != "${VERSION%%-*}" ]; then pre=${VERSION#*-}; v=${VERSION%%-*}${pre//./}; fi
    ARCH=$arch VERSION=$v STAGE=$STAGE "$STAGE/bin/nfpm" package --config "$STAGE/nfpm.yaml" --packager "$p" --target "$OUT/" >/dev/null
  done
done

printf '{"version":"%s","published":"%s","notes":"%s"}\n' "$VERSION" "$(date -u +%F)" "$NOTES_URL" > "$OUT/latest.json"
ls -1 "$OUT"
echo "Built rerouted $VERSION in $OUT"
