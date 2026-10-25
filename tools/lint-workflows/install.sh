#!/bin/sh
# install.sh <tool> -- download (or re-verify) one workflow-lint tool at the
# version pinned in .workflow-lint-tools and print the path of its binary on
# stdout. Used only by `make lint-workflows`, from the repository root.
#
# Integrity. The pin file carries, per tool, either
#   checksums=<sha256>       the sha256 of the release's *_checksums.txt; the
#                            archive is then checked against its line in that
#                            file, so one in-repo hash covers every OS/arch, or
#   <os>_<arch>=<sha256>     the sha256 of the platform's asset itself, for
#                            releases without a usable checksums file
#                            (shellcheck publishes none; yq's needs a second
#                            column-order file to read).
# Every run re-hashes the cached download against the pin and re-extracts the
# binary from it, so editing a pin (or the cache) takes effect immediately and a
# mismatch stops `make lint-workflows` before any tool runs.
#
# Layout: bin/tools/<tool>-<version>/ (gitignored via bin/, removed by
# `make clean`). The version is in the path, so a bump downloads afresh.
#
# No `curl | sh`, no third-party installer, no GitHub Action: CI runs exactly
# this script through `make`, so local and CI binaries are identical.
set -eu
set -f # no globbing: pin-file fields are split on purpose, never expanded

PIN_FILE=.workflow-lint-tools
TOOLS="pinact ghalint actionlint shellcheck yq"
GH=https://github.com

die() {
	echo "lint-workflows: $*" >&2
	exit 1
}

[ $# -eq 1 ] || die "usage: $0 <tool>   (one of: $TOOLS)"
tool=$1
case " $TOOLS " in *" $tool "*) ;; *) die "unknown tool '$tool' (expected one of: $TOOLS)" ;; esac

# --- validate the pin file's shape --------------------------------------------
[ -f "$PIN_FILE" ] || die "$PIN_FILE is missing (run from the repository root)."
if tr -d '\n' <"$PIN_FILE" | grep -q "$(printf '\r')"; then
	die "$PIN_FILE has CRLF line endings; re-check it out with LF (.gitattributes pins this)."
fi
lineno=0
seen=" "
while IFS= read -r line || [ -n "$line" ]; do
	lineno=$((lineno + 1))
	case "$line" in '' | '#'*) continue ;; esac
	# shellcheck disable=SC2086 # deliberate field splitting
	set -- $line
	[ $# -ge 3 ] || die "$PIN_FILE:$lineno: expected '<tool> <vX.Y.Z> <hash>...', got: $line"
	name=$1 ver=$2
	shift 2
	case " $TOOLS " in *" $name "*) ;; *) die "$PIN_FILE:$lineno: unknown tool '$name'" ;; esac
	case "$seen" in *" $name "*) die "$PIN_FILE:$lineno: '$name' is pinned twice" ;; esac
	seen="$seen$name "
	printf '%s\n' "$ver" | grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+' ||
		die "$PIN_FILE:$lineno: version must look like vX.Y.Z, got '$ver'"
	for h in "$@"; do
		printf '%s\n' "$h" | grep -Eqx "(checksums|(linux|darwin)_(amd64|arm64))=[0-9a-f]{64}" ||
			die "$PIN_FILE:$lineno: hash must be checksums=<sha256> or <os>_<arch>=<sha256> (64 lowercase hex), got '$h'"
	done
done <"$PIN_FILE"
for t in $TOOLS; do
	case "$seen" in *" $t "*) ;; *) die "$PIN_FILE does not pin '$t'." ;; esac
done

# --- this tool's pin ------------------------------------------------------------
# shellcheck disable=SC2046 # deliberate field splitting
set -- $(grep -E "^${tool}[[:space:]]" "$PIN_FILE")
version=$2
shift 2
pins="$*"
v=${version#v}

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported OS '$(uname -s)': supported are linux and darwin (amd64 / arm64)." ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported CPU '$(uname -m)': supported are amd64 and arm64." ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	die "neither sha256sum nor shasum found."
fi

pin_value() { # pin_value <key> -> hash, or empty
	for p in $pins; do
		case "$p" in "$1="*) echo "${p#*=}" && return 0 ;; esac
	done
}

# Per-tool release layout: asset name, checksums-file name, binary in archive.
sumfile=
case "$tool" in
pinact)
	asset="pinact_${os}_${arch}.tar.gz"
	sumfile="pinact_${v}_checksums.txt"
	member=pinact
	repo=suzuki-shunsuke/pinact
	;;
ghalint)
	asset="ghalint_${v}_${os}_${arch}.tar.gz"
	sumfile="ghalint_${v}_checksums.txt"
	member=ghalint
	repo=suzuki-shunsuke/ghalint
	;;
actionlint)
	asset="actionlint_${v}_${os}_${arch}.tar.gz"
	sumfile="actionlint_${v}_checksums.txt"
	member=actionlint
	repo=rhysd/actionlint
	;;
shellcheck)
	case "$arch" in amd64) sarch=x86_64 ;; arm64) sarch=aarch64 ;; esac
	asset="shellcheck-${version}.${os}.${sarch}.tar.gz"
	member="shellcheck-${version}/shellcheck"
	repo=koalaman/shellcheck
	;;
yq)
	asset="yq_${os}_${arch}"
	member=
	repo=mikefarah/yq
	;;
esac
base="$GH/$repo/releases/download/$version"
dir="bin/tools/$tool-$version"
mkdir -p "$dir"

# fetch_verified <file> <expected sha256>: reuse the cached file if it matches,
# otherwise download it once and require a match.
fetch_verified() {
	if [ -f "$dir/$1" ] && [ "$(sha256 "$dir/$1")" = "$2" ]; then
		return 0
	fi
	echo "lint-workflows: downloading $tool $version: $1" >&2
	curl -fsSL --retry 3 -o "$dir/$1.tmp" "$base/$1" || die "download failed: $base/$1"
	got=$(sha256 "$dir/$1.tmp")
	if [ "$got" != "$2" ]; then
		rm -f "$dir/$1.tmp"
		die "checksum mismatch for $tool $version $1: pinned $2, got $got. Refusing to run it."
	fi
	mv "$dir/$1.tmp" "$dir/$1"
}

if [ -n "$sumfile" ]; then
	want=$(pin_value checksums)
	[ -n "$want" ] || die "$PIN_FILE: '$tool' needs checksums=<sha256 of $sumfile>."
	fetch_verified "$sumfile" "$want"
	want=$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1 }' "$dir/$sumfile")
	[ -n "$want" ] || die "$sumfile lists no entry for $asset."
else
	want=$(pin_value "${os}_${arch}")
	[ -n "$want" ] || die "$PIN_FILE: '$tool' has no ${os}_${arch}=<sha256> pin."
fi
fetch_verified "$asset" "$want"

# Re-extract on every run so the binary always comes from the verified asset.
bin="$dir/$tool"
if [ -z "$member" ]; then
	cp "$dir/$asset" "$bin"
else
	tar -xzf "$dir/$asset" -O "$member" >"$bin" || die "cannot extract $member from $asset"
fi
chmod +x "$bin"
echo "$bin"
