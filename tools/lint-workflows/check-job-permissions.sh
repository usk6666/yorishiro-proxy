#!/bin/sh
# check-job-permissions.sh <yq> <workflow.yml>... -- fail unless every job in
# every given workflow declares its own `permissions:` key.
#
# ghalint's job_permissions policy cannot enforce this: it only fires when the
# workflow has a top-level `permissions:` grant to inherit, and our workflows
# set `permissions: {}`, so a job that drops its block passes ghalint silently.
# Such a job fails closed (no token scopes), but the "every job declares its
# permissions" rule would then be review-only -- so it is checked here. The
# YAML is read with yq (pinned in .workflow-lint-tools), never with grep/sed.
set -eu

[ $# -ge 2 ] || { echo "usage: $0 <yq> <workflow.yml>..." >&2; exit 2; }
yq=$1
shift

rc=0
total=0
for wf in "$@"; do
	"$yq" -e '.jobs | type == "!!map"' "$wf" >/dev/null 2>&1 || {
		echo "job permissions guard: $wf: no 'jobs:' map." >&2
		rc=1
		continue
	}
	missing=$("$yq" '.jobs | to_entries[] | select(.value | has("permissions") | not) | .key' "$wf")
	if [ -n "$missing" ]; then
		echo "job permissions guard: $wf: jobs without their own 'permissions:': $(printf '%s\n' "$missing" | tr '\n' ' ' | sed 's/ $//')" >&2
		rc=1
	fi
	total=$((total + $("$yq" '.jobs | length' "$wf")))
done
[ "$rc" -eq 0 ] || exit 1
echo "job permissions: all $total jobs in $# workflows declare permissions"
