#!/usr/bin/env bash

######################################################################
# Inside the VM: install the prebuilt TrueNAS kernel and OpenZFS release
# debs, then build + install this TrueNAS Samba tree against them.
#
# Invoked with the TrueNAS train in the TRAIN environment
# variable.  The kernel image + UAPI headers (truenas/linux) and the OpenZFS
# userland + kmod debs (truenas/zfs) are consumed from the rolling
# <TRAIN>-nightly GitHub releases rather than built here, so Samba compiles
# against the same libzfs and UAPI headers TrueNAS ships.  The OpenZFS
# modules are prebuilt against one exact kernel, so the VM must reboot into
# it (qemu-3.5-restart.sh) before the tests can load zfs.ko.
# The script copies the kernel, OpenZFS and truenas-samba debs to
# /tmp/ci-debs on the host. The test jobs install them with
# qemu-3-install.sh.
######################################################################

set -eu

TRAIN="${TRAIN:?TRAIN must be set}"

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
#    linux-libc-dev.  The test jobs install the same debs from
#    /tmp/ci-debs.
##################################################################
.github/workflows/scripts/tn-fetch-debs.sh \
  truenas/zfs "$TRAIN" /tmp/ci-debs/zfs 'openzfs-*' > /dev/null
.github/workflows/scripts/tn-fetch-debs.sh \
  truenas/linux "$TRAIN" /tmp/ci-debs/kernel 'linux-image-*' 'linux-*libc-dev_*' > /dev/null
.github/workflows/scripts/tn-install-debs.sh kernel \
  /tmp/ci-debs/kernel /tmp/ci-debs/zfs

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
mkdir -p /tmp/ci-debs/samba
cp ../truenas-samba_*.deb /tmp/ci-debs/samba/

##################################################################
# 5. Install truenas-samba and verify the TrueNAS VFS modules were
#    built + packaged.
##################################################################
.github/workflows/scripts/tn-install-debs.sh samba /tmp/ci-debs/samba/*.deb

##################################################################
# 6. Now replace the distribution kernel with the TrueNAS kernel so the
#    next boot (qemu-3.5-restart.sh) can only use it, and the prebuilt
#    zfs.ko can load.
##################################################################
.github/workflows/scripts/tn-install-debs.sh only-truenas-kernel /tmp/ci-debs/kernel
REMOTE_SCRIPT

# Pull the updated ccache back to the host so actions/cache can save it.
echo "Saving ccache from VM for caching..."
mkdir -p /tmp/ccache
rsync -az debian@$VM_IP:~/.ccache/ /tmp/ccache/ || echo "Note: no ccache to save"

# The debs for the test jobs (an artifact of the workflow)
rsync -a debian@$VM_IP:/tmp/ci-debs/ /tmp/ci-debs/

# Reboot is required so the VM comes up on the TrueNAS kernel and the ZFS kmod
# loads cleanly for the test stage.
echo "Cleaning cloud-init and powering off VM..."
ssh debian@$VM_IP 'sudo cloud-init clean --logs && sync && sleep 2 && sudo poweroff' &

echo "Build complete; VM shutting down for restart"
