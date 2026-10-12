#!/usr/bin/env bash
# Fails when the vendored zolana/prover module, the test vectors or the cgo
# module's toolchain drift from the zolana revision pinned in
# upstream.lock.json. Set ZOLANA_SRC to an existing checkout to skip the clone.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock="$root/upstream.lock.json"

json() { python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$@"; }
repository="$(json "$lock" repository)"
tag="$(json "$lock" tag)"
revision="$(json "$lock" revision)"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo "upstream.lock.json revision must be a full commit" >&2; exit 1; }

failed=0
fail() { echo "drift: $*" >&2; failed=1; }
sha256() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{ print $1 }'; else sha256sum | awk '{ print $1 }'; fi; }

# The tag must still name the pinned commit: a moved tag means a re-cut release.
tagged="$(git ls-remote --tags "$repository" "refs/tags/$tag^{}" "refs/tags/$tag" | awk '{ print $1 }' | head -1)"
[[ "$tagged" == "$revision" ]] || fail "tag $tag is at ${tagged:-<missing>}, upstream.lock.json pins $revision"

source_dir="${ZOLANA_SRC:-}"
if [[ -z "$source_dir" ]]; then
  source_dir="$(mktemp -d "${TMPDIR:-/tmp}/zolana-upstream.XXXXXX")"
  trap 'rm -rf "$source_dir"' EXIT
  git -C "$source_dir" init -q
  git -C "$source_dir" remote add origin "$repository"
  git -C "$source_dir" fetch -q --depth=1 --filter=blob:none origin "$revision"
fi
upstream() { git -C "$source_dir" show "$revision:$1"; }
upstream_ls() { git -C "$source_dir" ls-tree --name-only "$revision" "$1/" 2>/dev/null | sed "s|^$1/||"; }

# Files that carry a documented local edit: compare after undoing it.
normalize() {
  case "$1" in
    prover/common/marshal.go) sed 's|fmt.Errorf("invalid number")|fmt.Errorf("invalid number: %s", s)|' ;;
    circuits/spp_transaction/shared/hash_chain_4_test.go | circuits/spp_transaction/shared/right_hash_chain_4_test.go)
      sed 's|"../../../test-vectors/|"../../../../../test-vectors/|' ;;
    circuits/gadget/nonzero_hash_chain_vectors_test.go | prover/common/input_flags_test.go)
      sed 's|"../../test-vectors/|"../../../../test-vectors/|' ;;
    prover/transcript/transcript_test.go) sed 's|"../../test-vectors/indexed-proof.json"|"../../../../sdk-libs/fixtures/indexed-proof.json"|' ;;
    *) cat ;;
  esac
}
# Files that exist only here: the bridges, the vectors, this repo's own files.
local_only() {
  case "$1" in
    prover-wasm/* | cgo/* | test-vectors/* | scripts/* | .github/* | .gitignore | LICENSE | README.md | upstream.lock.json) return 0 ;;
    circuits/spp_transaction/shared/web_fixture_test.go | prover/common/marshal_local_test.go) return 0 ;;
  esac
  return 1
}
# Upstream files the closure leaves out: GPU-only builds and their docs, and
# every test of the prover-test helper packages.
upstream_excluded() {
  case "$1" in
    prover/backend/README.md | prover/backend/aeglos-source.lock) return 0 ;;
    prover-test/*_test.go) return 0 ;;
  esac
  if [[ "$1" == *.go ]] && upstream "prover/server/$1" | grep -q '^//go:build.*aeglos' && ! upstream "prover/server/$1" | grep -q '^//go:build !aeglos'; then
    return 0
  fi
  return 1
}

# Every vendored file matches upstream, and every upstream file of a vendored
# Go package (a directory holding .go files) is here.
while read -r path; do
  local_only "$path" && continue
  if ! upstream "prover/server/$path" >/tmp/check-upstream.$$ 2>/dev/null; then
    fail "$path has no upstream prover/server/$path at $revision"
    continue
  fi
  [[ "$(normalize "$path" < "$root/$path" | sha256)" == "$(sha256 < /tmp/check-upstream.$$)" ]] ||
    fail "$path differs from prover/server/$path at $revision"
done < <(cd "$root" && git ls-files | sort)
rm -f /tmp/check-upstream.$$
while read -r dir; do
  while read -r name; do
    [[ -n "$name" ]] || continue
    path="${dir:+$dir/}$name"
    [[ -f "$root/$path" ]] && continue
    upstream_excluded "$path" && continue
    fail "upstream prover/server/$path is not vendored"
  done < <(upstream_ls "prover/server${dir:+/$dir}" | while read -r entry; do
    [[ -z "$entry" ]] && continue
    [[ "$(git -C "$source_dir" cat-file -t "$revision:prover/server${dir:+/$dir}/$entry" 2>/dev/null)" == blob ]] && echo "$entry"
  done)
done < <(cd "$root" && git ls-files '*.go' | grep -v '^prover-wasm/\|^cgo/' | xargs -n1 dirname | sort -u)

# Vendored vectors are upstream's.
for file in "$root"/test-vectors/*; do
  name="$(basename "$file")"
  case "$name" in
    indexed-proof.json) source="sdk-libs/fixtures/$name" ;;
    *) source="test-vectors/$name" ;;
  esac
  [[ "$(sha256 < "$file")" == "$(upstream "$source" | sha256)" ]] || fail "test-vectors/$name differs from $source at $revision"
done

# Both modules build with the Go and gnark that generated the keys.
for manifest in go.mod cgo/go.mod; do
  for module in go github.com/consensys/gnark github.com/consensys/gnark-crypto; do
    want="$(upstream prover/server/go.mod | awk -v m="$module" '$1 == m { print $2; exit }')"
    got="$(awk -v m="$module" '$1 == m { print $2; exit }' "$root/$manifest")"
    [[ "$got" == "$want" ]] || fail "$manifest pins $module $got, upstream uses $want"
  done
done

if [[ "$failed" -ne 0 ]]; then
  echo "vendored sources are out of sync with zolana $tag ($revision)" >&2
  exit 1
fi
echo "vendored sources match zolana $tag ($revision)"
