#!/bin/sh
# check-status-needs.sh <yq> <workflow.yml> -- fail unless the workflow's
# `status-check` job lists every other job in `needs:`, and nothing else.
#
# status-check is the only ci.yml check the branch ruleset requires, and it
# fails only when a job in its `needs:` failed or was cancelled. A job missing
# from that list can therefore fail without blocking the merge -- so the list is
# checked here rather than left to review. The YAML is read with yq (pinned in
# .workflow-lint-tools), never with grep/sed.
set -eu
export LC_ALL=C # sort and comm must collate identically

[ $# -eq 2 ] || { echo "usage: $0 <yq> <workflow.yml>" >&2; exit 2; }
yq=$1
wf=$2

words() { printf '%s\n' "$1" | tr '\n' ' ' | sed 's/ $//'; }

fail() {
	echo "status-check needs guard: $wf: $*" >&2
	exit 1
}

"$yq" -e '.jobs["status-check"] | type == "!!map"' "$wf" >/dev/null 2>&1 ||
	fail "no 'status-check' job."
"$yq" -e '.jobs["status-check"].needs | type == "!!seq"' "$wf" >/dev/null 2>&1 ||
	fail "status-check 'needs:' must be a list of job ids."

jobs=$("$yq" '.jobs | keys | .[] | select(. != "status-check")' "$wf" | sort)
needs=$("$yq" '.jobs["status-check"].needs[]' "$wf" | sort)

dups=$(printf '%s\n' "$needs" | uniq -d)
[ -z "$dups" ] || fail "status-check 'needs:' lists a job twice: $(words "$dups")"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "$jobs" >"$tmp/jobs"
printf '%s\n' "$needs" >"$tmp/needs"
missing=$(comm -23 "$tmp/jobs" "$tmp/needs")
extra=$(comm -13 "$tmp/jobs" "$tmp/needs")

if [ -n "$missing" ] || [ -n "$extra" ]; then
	[ -z "$missing" ] || echo "status-check needs guard: missing from status-check 'needs:': $(words "$missing")" >&2
	[ -z "$extra" ] || echo "status-check needs guard: in status-check 'needs:' but not a job: $(words "$extra")" >&2
	fail "every other job must be listed in status-check 'needs:' (see the comment above that job)."
fi
echo "status-check needs: all $(printf '%s\n' "$jobs" | wc -l | tr -d ' ') jobs listed"
