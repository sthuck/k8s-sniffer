#!/usr/bin/env bash
# Compute the next release tag. Prints VERSION= and PREVIOUS_TAG= to stdout.
# When GITHUB_OUTPUT is set, also writes version= and previous_tag= there.
#
# Default: bump the minor of the latest vMAJOR.MINOR.PATCH tag (v0.1.0 if none).
# Override: --version vX.Y.Z (leading v optional). Manual versions must be
# greater than the current latest tag.
set -euo pipefail

usage() {
	echo "Usage: $0 [--version vX.Y.Z]" >&2
	exit 2
}

manual=""
while [ $# -gt 0 ]; do
	case "$1" in
	--version)
		[ $# -ge 2 ] || usage
		manual="$2"
		shift 2
		;;
	--version=*)
		manual="${1#--version=}"
		shift
		;;
	-h | --help)
		usage
		;;
	*)
		usage
		;;
	esac
done

normalize() {
	local v="$1"
	v="${v#v}"
	printf 'v%s\n' "$v"
}

is_semver() {
	[[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

latest_tag() {
	git tag -l 'v*.*.*' --sort=v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | tail -n1 || true
}

bump_minor() {
	local ver="${1#v}"
	local major minor patch
	IFS=. read -r major minor patch <<<"$ver"
	printf 'v%s.%s.0\n' "$major" "$((minor + 1))"
}

# True if $1 is a greater semver than $2 (both vMAJOR.MINOR.PATCH).
version_gt() {
	[ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$1" ]
}

latest="$(latest_tag)"

if [ -n "$manual" ]; then
	version="$(normalize "$manual")"
	if ! is_semver "$version"; then
		echo "invalid version '$manual': want vMAJOR.MINOR.PATCH" >&2
		exit 1
	fi
	if [ -n "$latest" ] && ! version_gt "$version" "$latest"; then
		echo "version $version is not greater than latest $latest" >&2
		exit 1
	fi
elif [ -z "$latest" ]; then
	version="v0.1.0"
else
	version="$(bump_minor "$latest")"
fi

if git show-ref --tags --verify --quiet "refs/tags/${version}"; then
	echo "tag ${version} already exists" >&2
	exit 1
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
	{
		printf 'version=%s\n' "$version"
		printf 'previous_tag=%s\n' "$latest"
	} >>"$GITHUB_OUTPUT"
fi

echo "Releasing ${version} (previous: ${latest:-none})" >&2
printf 'VERSION=%s\n' "$version"
printf 'PREVIOUS_TAG=%s\n' "$latest"
