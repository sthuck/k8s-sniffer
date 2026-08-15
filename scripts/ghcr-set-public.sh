#!/usr/bin/env bash
# Mark a GHCR container package public. Usage: ghcr-set-public.sh PACKAGE_NAME
# Env: GITHUB_REPOSITORY_OWNER, OWNER_TYPE (User|Organization), GH_TOKEN.
set -euo pipefail

name="${1:?package name required}"
owner="${GITHUB_REPOSITORY_OWNER:?}"
owner_type="${OWNER_TYPE:-User}"

if [ "$owner_type" = "Organization" ]; then
	pkg_path="/orgs/${owner}/packages/container/${name}"
	settings="https://github.com/orgs/${owner}/packages/container/${name}/settings"
else
	pkg_path="/users/${owner}/packages/container/${name}"
	settings="https://github.com/users/${owner}/packages/container/${name}/settings"
fi

visibility="$(gh api "$pkg_path" --jq .visibility 2>/dev/null || true)"
if [ "$visibility" = "public" ]; then
	echo "${name} is already public"
	exit 0
fi

if gh api --method PUT "${pkg_path}/visibility" -f visibility=public >/dev/null; then
	echo "Set ${name} public"
	exit 0
fi

echo "Could not set ${name} public via API (new GHCR packages default to private)." >&2
echo "Set it public once at: ${settings}" >&2
exit 1
