#!/usr/bin/env bash

######################################################################
# Fetch and build the pinned upstream liburing that vfs_io_uring is built
# against.
#
# Debian trixie ships liburing 2.9, which predates the io_uring work in the
# TrueNAS kernel this Samba runs on, so vfs_io_uring is built against
# upstream instead of liburing-dev.  The tree is cloned at build time from a
# pinned tag rather than vendored into this repo, so no third-party source is
# carried here.
#
# Only a *static* library is built (ENABLE_SHARED=0), compiled -fPIC so it
# links into vfs_io_uring.so.  That is what keeps the swap invisible outside
# the build: the shipped module carries no DT_NEEDED on liburing.so.2, so
# truenas-samba gains no runtime dependency on Debian's older liburing2 and
# cannot silently end up running against it.
#
# The staged install tree is written to debian/liburing/stage;
# debian/rules puts its pkgconfig directory on PKG_CONFIG_PATH so that
# source3/wscript's `CHECK_CFG(package='liburing')` finds this liburing.
# Set SAMBA_LIBURING_SRC to an existing tree to build from it instead of
# cloning (offline / air-gapped builds).
#
# LIBURING_COMMIT is the real pin -- a tag is mutable, a sha is not.
######################################################################

set -eu

LIBURING_URL="https://github.com/axboe/liburing.git"
LIBURING_TAG="liburing-2.15"
LIBURING_COMMIT="d41bf9220ec39277ff235379e9089d9e0fd6c2a5"
LIBURING_VERSION="${LIBURING_TAG#liburing-}"

# The shallow clone is the one build step that reaches the network; a github
# hiccup or rate-limit should not fail the package build on the first attempt.
CLONE_RETRIES=3

# Everything lives under one directory, so `rm -rf debian/liburing` (see
# debian/rules' dh_auto_clean override) is a complete clean.
ROOT="$(cd "$(dirname "$0")" && pwd)/liburing"
SRC="$ROOT/src"
STAGE="$ROOT/stage"

if [ -n "${SAMBA_LIBURING_SRC:-}" ]; then
    # The builder chose this tree explicitly, so the commit is not checked --
    # it may legitimately be an export without .git.
    SRC="$(cd "$SAMBA_LIBURING_SRC" 2>/dev/null && pwd)" || {
        echo "FATAL: SAMBA_LIBURING_SRC=$SAMBA_LIBURING_SRC is not a directory" >&2
        exit 1
    }
    echo "Using pre-seeded liburing tree: $SRC"
else
    # Idempotent: a tree already at the pinned commit is reused as-is, so a
    # repeated build does not re-clone.  Anything else is discarded rather
    # than fetched into -- a shallow clone has no history to move through,
    # and a stale tree is not worth repairing.
    if [ -d "$SRC/.git" ] &&
       [ "$(git -C "$SRC" rev-parse HEAD 2>/dev/null || true)" != "$LIBURING_COMMIT" ]; then
        rm -rf "$SRC"
    fi

    if [ ! -d "$SRC" ]; then
        mkdir -p "$ROOT"
        attempt=1
        # A --depth 1 clone is a single fetch with nothing to resume, so a
        # failure is retried from scratch: the partial tree (which the next
        # attempt would refuse to clone into) is discarded first.
        until git clone --depth 1 --branch "$LIBURING_TAG" "$LIBURING_URL" "$SRC"; do
            rm -rf "$SRC"
            if [ "$attempt" -ge "$CLONE_RETRIES" ]; then
                echo "FATAL: could not clone $LIBURING_TAG from $LIBURING_URL" >&2
                exit 1
            fi
            echo "liburing clone failed (attempt $attempt/$CLONE_RETRIES), retrying..." >&2
            sleep $((2 * attempt))
            attempt=$((attempt + 1))
        done
    fi

    head="$(git -C "$SRC" rev-parse HEAD)"
    if [ "$head" != "$LIBURING_COMMIT" ]; then
        echo "FATAL: $LIBURING_TAG resolved to $head, expected $LIBURING_COMMIT --" >&2
        echo "refusing to build against an unexpected tree" >&2
        exit 1
    fi
fi

# Configure with the staging prefix rather than /usr + DESTDIR: the generated
# liburing.pc records $prefix literally, and it has to point at the staged
# tree for pkg-config to hand configure the right -I/-L.
#
# --use-libc suppresses CONFIG_NOLIBC.  Upstream's default on x86-64 (and
# aarch64/riscv64) is the freestanding build -- -nostdlib -nodefaultlibs
# -ffreestanding, with liburing's own malloc/memset shims -- which has no
# business inside a libc-linked Samba module.
rm -rf "$STAGE"
(cd "$SRC" && ./configure --prefix="$STAGE/usr" --use-libc)

# ENABLE_SHARED=0 leaves only liburing.a in the staged libdir, so the
# `-luring` in liburing.pc can only resolve statically.  -fPIC is what makes
# that archive linkable into vfs_io_uring.so; without it the module link
# fails with "recompile with -fPIC".  CFLAGS otherwise comes from
# dpkg-buildflags (debian/rules exports it), keeping the hardening flags
# consistent with the rest of the package.
make -C "$SRC" ENABLE_SHARED=0 CFLAGS="${CFLAGS:--g -O2} -fPIC" install

# Guard the two ways the staging can silently come out wrong and leave
# configure to pick up a system liburing (or nothing) instead.
if [ ! -f "$STAGE/usr/lib/liburing.a" ]; then
    echo "FATAL: liburing.a was not staged in $STAGE/usr/lib" >&2
    exit 1
fi
if ls "$STAGE"/usr/lib/liburing.so* >/dev/null 2>&1; then
    echo "FATAL: a shared liburing was staged; -luring would link dynamically" >&2
    exit 1
fi

staged_version="$(PKG_CONFIG_PATH="$STAGE/usr/lib/pkgconfig" \
    pkg-config --modversion liburing)"
if [ "$staged_version" != "$LIBURING_VERSION" ]; then
    echo "FATAL: staged liburing.pc reports $staged_version, expected $LIBURING_VERSION" >&2
    exit 1
fi

echo "Staged liburing $staged_version (static, PIC) in $STAGE"
