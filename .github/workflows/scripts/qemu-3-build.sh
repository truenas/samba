#!/usr/bin/env bash

######################################################################
# Inside the VM: install the prebuilt TrueNAS kernel and OpenZFS release
# debs, then build + install this TrueNAS Samba tree against them.
#
# Invoked with the TrueNAS train (master or 26) in the TRAIN environment
# variable.  The kernel image + UAPI headers (truenas/linux) and the OpenZFS
# userland + kmod debs (truenas/zfs) are consumed from the rolling
# <TRAIN>-nightly GitHub releases rather than built here, so Samba compiles
# against the same libzfs and UAPI headers TrueNAS ships.  The OpenZFS
# modules are prebuilt against one exact kernel, so the VM must reboot into
# it (qemu-3.5-restart.sh) before the tests can load zfs.ko.
######################################################################

set -eu

TRAIN="${TRAIN:?TRAIN must be set (master or 26)}"

echo "Installing prebuilt TrueNAS kernel + OpenZFS ($TRAIN train) and building Samba..."

source /tmp/vm-info.sh

echo "Waiting for cloud-init to complete..."
ssh debian@$VM_IP "cloud-init status --wait" || true

echo "Installing rsync in VM..."
ssh debian@$VM_IP "sudo apt-get update && sudo apt-get install -y rsync"

# Copy the Samba source tree into the VM (skip VCS + build artifacts). This
# also brings the .github/workflows/scripts helpers the remote script calls,
# e.g. tn-fetch-debs.sh.
echo "Copying Samba source to VM..."
ssh debian@$VM_IP "mkdir -p ~/samba"
rsync -az --delete \
  --exclude='.git' \
  --exclude='/bin/' \
  --exclude='*.o' --exclude='*.lo' \
  "$GITHUB_WORKSPACE/" debian@$VM_IP:~/samba/

# Restore ccache (Samba build accelerator) into the VM if a cache was restored.
if [ -d /tmp/ccache ] && [ -n "$(ls -A /tmp/ccache 2>/dev/null || true)" ]; then
  echo "Restoring ccache into VM..."
  ssh debian@$VM_IP "mkdir -p ~/.ccache"
  rsync -az /tmp/ccache/ debian@$VM_IP:~/.ccache/
fi

echo "Building in VM..."
ssh debian@$VM_IP bash -s "$TRAIN" <<'REMOTE_SCRIPT'
TRAIN="$1"
set -eu
export DEBIAN_FRONTEND=noninteractive

cd ~/samba
sudo apt-get update

##################################################################
# 1. Host tooling. curl/jq/ca-certificates fetch and verify the
#    release assets; build-essential/devscripts/equivs/ccache build
#    the deb; git is what debian/build-liburing.sh uses to clone the
#    pinned upstream liburing during the build.
##################################################################
sudo apt-get install -y \
  build-essential \
  devscripts \
  equivs \
  ccache \
  git \
  curl \
  jq \
  ca-certificates

##################################################################
# 2. Prebuilt TrueNAS kernel + OpenZFS from the <TRAIN>-nightly
#    releases.  Alongside the bootable image we pull the kernel's
#    linux-*libc-dev package: Samba (and the liburing it is built
#    against) compiles against the kernel's UAPI headers, and
#    debian/control requires the TrueNAS ones, not the stock
#    linux-libc-dev.
##################################################################
ZFS_MANIFEST="$(.github/workflows/scripts/tn-fetch-debs.sh \
  truenas/zfs "$TRAIN" /tmp/zfs-debs 'openzfs-*')"
KERNEL_MANIFEST="$(.github/workflows/scripts/tn-fetch-debs.sh \
  truenas/linux "$TRAIN" /tmp/tn-kernel 'linux-image-*' 'linux-*libc-dev_*')"

# The OpenZFS kmod is built against one exact kernel.  The kernel and zfs
# nightlies roll independently, so if the kernel has advanced past the one
# zfs was built against, the prebuilt zfs.ko will not load.  Refuse to
# proceed on a mismatch with a clear message rather than failing later at
# modprobe time.
ZFS_KREL="$(jq -r '.kernel_release' "$ZFS_MANIFEST")"
RELEASE="$(jq -r '.release' "$KERNEL_MANIFEST")"
if [ "$ZFS_KREL" != "$RELEASE" ]; then
  echo "FATAL: OpenZFS $TRAIN-nightly debs were built against kernel $ZFS_KREL,"
  echo "but truenas/linux $TRAIN-nightly currently publishes kernel $RELEASE."
  echo "The two rolling nightlies are out of sync; the prebuilt zfs.ko cannot"
  echo "load under the mismatched kernel.  This self-heals once the truenas/zfs"
  echo "nightly rebuilds against $RELEASE."
  exit 1
fi
echo "Kernel release: $RELEASE (matches the OpenZFS build kernel)"

# Install the kernel image first so /lib/modules/$RELEASE exists and the
# OpenZFS modules deb's linux-image dependency resolves; the libc-dev package
# Provides/Conflicts the stock linux-libc-dev, so it replaces it for the
# Samba build.
echo "Installing TrueNAS kernel image + UAPI headers..."
sudo -E apt-get install -y \
  /tmp/tn-kernel/linux-image-*.deb \
  /tmp/tn-kernel/linux-*libc-dev_*.deb

# Install the OpenZFS userland + kmod debs (the release already excludes
# dkms/dracut).  These provide the libzfs7 / libzfs7-devel / libnvpair3 /
# libuutil3 that Samba's Build-Depends name (the package names differ; the
# virtual names they Provide match).
echo "Installing OpenZFS debs..."
sudo -E apt-get install -y /tmp/zfs-debs/openzfs-*.deb
sudo depmod -a "$RELEASE"

# The prebuilt zfs.ko must have landed under the TrueNAS kernel's modules
# tree, or the post-reboot modprobe will fail.  Fail loudly here instead.
ZFS_KO="$(find "/lib/modules/$RELEASE" -name 'zfs.ko*' -print -quit 2>/dev/null || true)"
if [ -z "$ZFS_KO" ]; then
  echo "FATAL: no zfs.ko under /lib/modules/$RELEASE/ after installing the OpenZFS modules deb"
  echo "Installed zfs.ko paths in /lib/modules:"
  find /lib/modules -name 'zfs.ko*' 2>/dev/null || echo "  (none found)"
  exit 1
fi
echo "Found zfs.ko at: $ZFS_KO"

echo "Installed ZFS userland packages:"
dpkg -l | grep -Ei 'libzfs|libnvpair|libuutil|libzpool' || true

##################################################################
# 3. The rest of Samba's build dependencies.
##################################################################
echo "Installing Samba build dependencies..."
sudo apt-get build-dep -y . || {
  echo "apt-get build-dep failed; retrying via mk-build-deps..."
  sudo mk-build-deps --install --remove \
    --tool='apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y' \
    debian/control
}

# Resolving the build-deps could in principle have swapped the TrueNAS UAPI
# headers back out for the stock linux-libc-dev (they Conflict). Building
# against the TrueNAS headers is the point of this job, so check.
if ! dpkg-query -W -f='${Status}' linux-truenas-production-libc-dev 2>/dev/null \
     | grep -q '^install ok installed$'; then
  echo "FATAL: linux-truenas-production-libc-dev is not installed after build-dep;"
  echo "Samba would compile against the stock linux-libc-dev instead."
  dpkg -l 'linux-*libc-dev' || true
  exit 1
fi

# Fail fast (before the long build) with a clear message if any Build-Depends
# is still unmet -- e.g. if the openzfs dev package that Provides
# libzfs7-devel was not produced/installed.
echo "Confirming all Samba Build-Depends are satisfied..."
if ! dpkg-checkbuilddeps; then
  echo "FATAL: unmet Samba build dependencies (see above)."
  echo "Installed openzfs packages and what they Provide:"
  dpkg-query -W -f='${Package}\tProvides: ${Provides}\n' 'openzfs-*' 2>/dev/null || true
  exit 1
fi

##################################################################
# 4. Build Samba (waf via dpkg-buildpackage, configured --with-libzfs).
#    debian/rules also clones + builds the pinned upstream liburing here
#    and points configure at it, so this stage needs network access.
##################################################################
echo "Building Samba (this is the long pole)..."
# Route the compiler through ccache to speed up subsequent rebuilds.
export PATH="/usr/lib/ccache:$PATH"
export CCACHE_DIR="$HOME/.ccache"
export CCACHE_MAXSIZE="2G"
ccache -z >/dev/null 2>&1 || true
DEB_BUILD_OPTIONS="parallel=$(nproc)" dpkg-buildpackage -us -uc -b
echo "ccache stats after build:"; ccache -s || true

echo "Installing truenas-samba..."
sudo apt-get install -y $(ls ../truenas-samba_*.deb) || {
  sudo dpkg -i ../truenas-samba_*.deb || true
  sudo apt-get install -f -y
}

##################################################################
# 5. Verify the TrueNAS VFS modules were built + packaged.
##################################################################
echo "Verifying TrueNAS VFS modules are present..."
VFS_DIR="$(dirname "$(find /usr/lib -path '*/samba/vfs/zfs_core.so' -print -quit)")"
echo "VFS module dir: ${VFS_DIR:-<not found>}"
MISSING=0
# io_uring is in the list because it is the module that proves the pinned
# upstream liburing was found: source3/wscript only adds vfs_io_uring to the
# default module set when configure detected liburing.
for m in truenas_streams_xattr zfs_core ixnas tmprotect shadow_copy_zfs truenas_audit io_uring; do
  if [ -n "${VFS_DIR:-}" ] && [ -e "$VFS_DIR/$m.so" ]; then
    echo "  ok   $m.so"
  else
    echo "  MISS $m.so"
    MISSING=1
  fi
done
if [ "$MISSING" -ne 0 ]; then
  echo "FATAL: one or more expected TrueNAS VFS modules are missing"
  ls -l "${VFS_DIR:-/usr/lib}" || true
  exit 1
fi
echo "All expected TrueNAS VFS modules built and installed."

##################################################################
# 6. Now replace the distribution kernel with the TrueNAS kernel so the
#    next boot (qemu-3.5-restart.sh) can only use it, and the prebuilt
#    zfs.ko can load.
##################################################################
echo "Removing distribution kernels so the TrueNAS kernel is the default..."
# Let apt remove the running (stock) kernel without aborting.
echo 'linux-base linux-base/removing-running-kernel boolean false' | \
  sudo debconf-set-selections
# TrueNAS kernel packages carry version-free names
# (linux-{image,headers}-truenas-production-amd64), so tell them apart from
# the distribution kernels by name.
STOCK=$(dpkg-query -W -f '${Package}\n' 'linux-image-*' 'linux-headers-*' | \
  grep -v -- truenas || true)
if [ -n "$STOCK" ]; then
  sudo -E apt-get purge -y $STOCK
fi
sudo update-grub

# The TrueNAS kernel must now be the one and only installed kernel.
test -e "/boot/vmlinuz-$RELEASE"
test "$(ls /boot/vmlinuz-* | wc -l)" -eq 1
echo "TrueNAS kernel $RELEASE is the only installed kernel."
REMOTE_SCRIPT

# Pull the updated ccache back to the host so actions/cache can save it.
echo "Saving ccache from VM for caching..."
mkdir -p /tmp/ccache
rsync -az debian@$VM_IP:~/.ccache/ /tmp/ccache/ || echo "Note: no ccache to save"

# Reboot is required so the VM comes up on the TrueNAS kernel and the ZFS kmod
# loads cleanly for the test stage.
echo "Cleaning cloud-init and powering off VM..."
ssh debian@$VM_IP 'sudo cloud-init clean --logs && sync && sleep 2 && sudo poweroff' &

echo "Build complete; VM shutting down for restart"
