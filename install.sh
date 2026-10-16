#!/bin/sh
# Builds ghostd from source and installs it, then runs `ghostd setup`.
#
# From a checkout:   sh install.sh [options] [-- <ghostd setup options>]
# Piped from a tag:  curl -fsSL https://raw.githubusercontent.com/gigahost-apps/ghostd/<tag>/install.sh | sh -s -- [options] [-- <ghostd setup options>]
#
# Options:
#   --ref <tag|branch|commit>  what to build when piped (default: the latest tag)
#   --prefix <dir>             install <dir>/bin/ghostd (default: $HOME/.local, /usr/local as root)
#   --no-rustup                fail instead of installing rustup when cargo is missing
#
# It never runs a package manager: when something is missing it says what
# to install and stops. It builds a static (musl) binary with the toolchain
# pinned in rust-toolchain.toml and removes its temporary files when it
# ends.

set -eu

API_URL="https://api.github.com/repos/gigahost-apps/ghostd"
CODELOAD_URL="https://codeload.github.com/gigahost-apps/ghostd/tar.gz"
RUSTUP_URL="https://sh.rustup.rs"

say() {
    printf 'ghostd install: %s\n' "$*" >&2
}

die() {
    say "$*"
    exit 1
}

usage() {
    cat >&2 <<'USAGE'
usage: sh install.sh [--ref <tag|branch|commit>] [--prefix <dir>] [--no-rustup] [-- <ghostd setup options>]

  --ref <ref>     what to build when piped (default: the latest tag)
  --prefix <dir>  install <dir>/bin/ghostd (default: $HOME/.local, /usr/local as root)
  --no-rustup     fail instead of installing rustup when cargo is missing
USAGE
}

have() {
    command -v "$1" >/dev/null 2>&1
}

ref=""
prefix=""
no_rustup=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --ref)
            [ "$#" -ge 2 ] || die "--ref needs a value"
            ref="$2"
            shift 2
            ;;
        --ref=*)
            ref="${1#--ref=}"
            shift
            ;;
        --prefix)
            [ "$#" -ge 2 ] || die "--prefix needs a value"
            prefix="$2"
            shift 2
            ;;
        --prefix=*)
            prefix="${1#--prefix=}"
            shift
            ;;
        --no-rustup)
            no_rustup=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            die "unknown option $1 (options for ghostd setup go after --)"
            ;;
    esac
done
# What remains in "$@" goes to `ghostd setup`.

case "$ref" in
    *[!A-Za-z0-9._/-]*) die "--ref holds characters a tag, branch or commit does not: $ref" ;;
esac

# Where the source comes from: the checkout this script sits in, or a
# download when it is piped.
src=""
case "$0" in
    *install.sh)
        dir=$(cd "$(dirname "$0")" && pwd)
        if [ -f "$dir/Cargo.toml" ] && grep -q 'crates/ghostd' "$dir/Cargo.toml" &&
            [ -f "$dir/rust-toolchain.toml" ]; then
            src="$dir"
        fi
        ;;
esac
if [ -n "$src" ] && [ -n "$ref" ]; then
    die "this is a checkout: it builds what is checked out (check out $ref with git first, or pipe the script to build a ref)"
fi

# Checks, each saying what to do.
os=$(uname -s)
[ "$os" = Linux ] || die "ghostd runs on Linux only, not on $os"
arch=$(uname -m)
case "$arch" in
    x86_64 | amd64 | aarch64 | arm64) ;;
    *) die "ghostd is built for x86_64 and aarch64, not $arch" ;;
esac

hint_packages() {
    say "install $1, for example with one of:"
    say "  sudo apt-get install -y $2"
    say "  sudo apk add $3"
    say "  sudo dnf install -y $4"
    say "  sudo pacman -S --needed $5"
}

need_download=0
if [ -z "$src" ]; then
    need_download=1
fi
if ! have cargo && ! [ -x "$HOME/.cargo/bin/cargo" ]; then
    need_download=1
fi
if [ "$need_download" -eq 1 ]; then
    if ! have curl && ! have wget; then
        hint_packages "curl (or wget)" "curl" "curl" "curl" "curl"
        exit 1
    fi
    if [ -z "$src" ] && ! have tar; then
        hint_packages "tar" "tar" "tar" "tar" "tar"
        exit 1
    fi
fi
if ! have cc && ! have gcc && ! have clang; then
    hint_packages "a C compiler (cc, gcc or clang; Rust needs it to link)" \
        "build-essential" "build-base" "gcc" "base-devel"
    exit 1
fi

# fetch <url> <file>
fetch() {
    if have curl; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
    else
        wget -q -O "$2" "$1"
    fi
}

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t ghostd-install)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' INT TERM HUP

# Cargo: on the PATH, in ~/.cargo/bin, or installed now through rustup.
if ! have cargo && [ -x "$HOME/.cargo/bin/cargo" ]; then
    PATH="$HOME/.cargo/bin:$PATH"
    export PATH
fi
if ! have cargo; then
    if [ "$no_rustup" -eq 1 ]; then
        die "cargo is missing; install Rust (see https://rustup.rs) or run without --no-rustup"
    fi
    say "cargo is missing: installing rustup for $(id -un) into $HOME/.cargo from $RUSTUP_URL"
    fetch "$RUSTUP_URL" "$tmp/rustup-init.sh" || die "cannot download $RUSTUP_URL"
    sh "$tmp/rustup-init.sh" -y --profile minimal --default-toolchain none ||
        die "rustup's installer failed"
    PATH="$HOME/.cargo/bin:$PATH"
    export PATH
fi

if [ -z "$src" ]; then
    if [ -z "$ref" ]; then
        # Only an answer that lists no tag at all means main; a failed call
        # (GitHub allows 60 unauthenticated API calls an hour per address,
        # which a shared or NAT address may have used up) never does.
        fetch "$API_URL/tags" "$tmp/tags.json" ||
            die "cannot list the release tags from GitHub's API (its limit is 60 calls an hour per address without a token): pass --ref <tag>, the latest from https://github.com/gigahost-apps/ghostd/tags"
        # One field per line first, so that the first tag's name is taken
        # however the JSON is laid out.
        ref=$(tr ',{}' '\n\n\n' <"$tmp/tags.json" |
            sed -n 's/^[[:space:]]*"name":[[:space:]]*"\([A-Za-z0-9._/-]*\)"[[:space:]]*$/\1/p' | head -n 1)
        if [ -z "$ref" ]; then
            [ "$(tr -d ' \t\r\n' <"$tmp/tags.json")" = "[]" ] ||
                die "cannot read the release tags GitHub's API answered: pass --ref <tag>"
            ref=main
            say "the repository has no release tag yet: building main"
        fi
    fi
    commit=""
    if fetch "$API_URL/commits/$ref" "$tmp/commit.json"; then
        commit=$(grep -o '"sha": *"[0-9a-f]\{40\}"' "$tmp/commit.json" | head -n 1 |
            sed 's/.*"\([0-9a-f]\{40\}\)"/\1/')
    fi
    if [ -n "$commit" ]; then
        say "building $ref ($commit)"
        archive="$CODELOAD_URL/$commit"
    else
        say "cannot resolve $ref to a commit (GitHub's API refused?): building $ref as downloaded"
        commit=unknown
        archive="$CODELOAD_URL/$ref"
    fi
    fetch "$archive" "$tmp/source.tar.gz" || die "cannot download $archive"
    mkdir "$tmp/source"
    tar -xzf "$tmp/source.tar.gz" -C "$tmp/source" || die "cannot unpack $archive"
    src=$(find "$tmp/source" -mindepth 1 -maxdepth 1 -type d | head -n 1)
    [ -n "$src" ] && [ -f "$src/Cargo.toml" ] || die "the archive holds no ghostd source"
else
    commit=unknown
    ref=checkout
    if have git && git -C "$src" rev-parse HEAD >/dev/null 2>&1; then
        commit=$(git -C "$src" rev-parse HEAD)
        ref=$(git -C "$src" describe --tags --always --dirty 2>/dev/null || printf '%s' "$commit")
    fi
    say "building the checkout in $src ($ref)"
fi

# The toolchain rust-toolchain.toml pins (rustup installs it on first use;
# a cargo without rustup must be that version or newer).
if have rustup; then
    (cd "$src" && { rustup toolchain install >/dev/null 2>&1 || rustup show >/dev/null; }) ||
        die "rustup cannot install the toolchain rust-toolchain.toml pins"
else
    say "no rustup: building with $(cargo --version 2>/dev/null || printf 'cargo') (ghostd needs Rust 1.97 or newer)"
fi

# A static binary (musl), as CI and the release channel build it, so that
# it runs whatever the machine's C library becomes.
case "$arch" in
    x86_64 | amd64) triple=x86_64-unknown-linux-musl ;;
    *) triple=aarch64-unknown-linux-musl ;;
esac
if have rustup; then
    (cd "$src" && rustup target add "$triple" >/dev/null) ||
        die "rustup cannot add the $triple target"
elif ! [ -d "$(rustc --print sysroot 2>/dev/null)/lib/rustlib/$triple" ]; then
    say "this Rust has no $triple target and no rustup to add it: building for the host's C library instead"
    triple=""
fi
if [ -n "$triple" ]; then
    (cd "$src" && CARGO_TARGET_DIR="$tmp/target" cargo build --release --locked -p ghostd --target "$triple") ||
        die "the build failed"
    binary="$tmp/target/$triple/release/ghostd"
else
    (cd "$src" && CARGO_TARGET_DIR="$tmp/target" cargo build --release --locked -p ghostd) ||
        die "the build failed"
    binary="$tmp/target/release/ghostd"
fi

if [ -z "$prefix" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        prefix=/usr/local
    else
        prefix="$HOME/.local"
    fi
fi
mkdir -p "$prefix/bin" || die "cannot create $prefix/bin"
cp "$binary" "$prefix/bin/ghostd.new" || die "cannot write $prefix/bin"
chmod 755 "$prefix/bin/ghostd.new"
mv -f "$prefix/bin/ghostd.new" "$prefix/bin/ghostd"
say "installed $prefix/bin/ghostd"

"$prefix/bin/ghostd" setup --origin source --ref "$ref" --commit "$commit" "$@"

if "$prefix/bin/ghostd" status 2>/dev/null | grep -q '"running":true'; then
    say "a ghostd daemon runs: the new binary takes effect after \`ghostd stop\` (the next \`ghostd stdio\` starts it again)"
fi
case ":$PATH:" in
    *":$prefix/bin:"*) ;;
    *) say "$prefix/bin is not on your PATH; a client runs ghostd by its full path ($prefix/bin/ghostd stdio), so ssh works anyway" ;;
esac
