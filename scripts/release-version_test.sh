#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/release-version.sh"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

run_in_repo() {
	(
		cd "$1"
		shift
		"$SCRIPT" "$@"
	)
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git init -q "$tmp/repo"
git -C "$tmp/repo" config user.email test@example.com
git -C "$tmp/repo" config user.name test
git -C "$tmp/repo" commit -q --allow-empty -m init

out="$(run_in_repo "$tmp/repo")"
[[ "$out" == $'VERSION=v0.1.0\nPREVIOUS_TAG=' ]] || fail "no tags: got $(printf %q "$out")"

git -C "$tmp/repo" tag v0.1.0
out="$(run_in_repo "$tmp/repo")"
[[ "$out" == $'VERSION=v0.2.0\nPREVIOUS_TAG=v0.1.0' ]] || fail "bump 0.1.0: got $(printf %q "$out")"

git -C "$tmp/repo" tag v0.9.3
git -C "$tmp/repo" tag v0.10.0
git -C "$tmp/repo" tag v0.2.0-rc.1
out="$(run_in_repo "$tmp/repo")"
[[ "$out" == $'VERSION=v0.11.0\nPREVIOUS_TAG=v0.10.0' ]] || fail "version sort: got $(printf %q "$out")"

out="$(run_in_repo "$tmp/repo" --version 1.4.0)"
[[ "$out" == $'VERSION=v1.4.0\nPREVIOUS_TAG=v0.10.0' ]] || fail "manual: got $(printf %q "$out")"

if run_in_repo "$tmp/repo" --version v0.1.0 >/dev/null 2>"$tmp/err"; then
	fail "expected older manual version to fail"
fi
grep -q 'not greater' "$tmp/err" || fail "older version error: $(cat "$tmp/err")"

if run_in_repo "$tmp/repo" --version v0.10.0 >/dev/null 2>"$tmp/err"; then
	fail "expected equal manual version to fail"
fi
grep -q 'not greater' "$tmp/err" || fail "equal version error: $(cat "$tmp/err")"

out="$(run_in_repo "$tmp/repo" --version v0.10.1)"
[[ "$out" == $'VERSION=v0.10.1\nPREVIOUS_TAG=v0.10.0' ]] || fail "manual patch: got $(printf %q "$out")"

if run_in_repo "$tmp/repo" --version not-a-version >/dev/null 2>"$tmp/err"; then
	fail "expected invalid version to fail"
fi
grep -q 'invalid version' "$tmp/err" || fail "invalid version error: $(cat "$tmp/err")"

GITHUB_OUTPUT="$tmp/ghout" run_in_repo "$tmp/repo" >/dev/null
grep -qx 'version=v0.11.0' "$tmp/ghout" || fail "GITHUB_OUTPUT version: $(cat "$tmp/ghout")"
grep -qx 'previous_tag=v0.10.0' "$tmp/ghout" || fail "GITHUB_OUTPUT previous: $(cat "$tmp/ghout")"

echo "release-version tests passed"
