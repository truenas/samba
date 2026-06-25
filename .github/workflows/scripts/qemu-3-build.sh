#!/usr/bin/env bash

######################################################################
# Inside the VM: build/install TrueNAS OpenZFS, then build + install
# this TrueNAS Samba tree against it.
######################################################################

set -eu

echo "Building ZFS + Samba in the VM..."

source /tmp/vm-info.sh
ZFS_BRANCH="${ZFS_BRANCH:-truenas/zfs-2.4-release}"

echo "Waiting for cloud-init to complete..."
ssh debian@$VM_IP "cloud-init status --wait" || true

echo "Installing rsync in VM..."
ssh debian@$VM_IP "sudo apt-get update && sudo apt-get install -y rsync"

# Restore cached ZFS debs to the VM if we have them.
if [ "${ZFS_CACHE_HIT:-}" = "true" ] && [ -d "/tmp/zfs-debs" ] && [ -n "$(ls -A /tmp/zfs-debs 2>/dev/null || true)" ]; then
  echo "Found cached OpenZFS packages, copying to VM..."
  ssh debian@$VM_IP "mkdir -p /tmp/zfs-debs"
  rsync -az /tmp/zfs-debs/ debian@$VM_IP:/tmp/zfs-debs/
  CACHED_ZFS="true"
else
  echo "No cached OpenZFS packages; will build from source"
  CACHED_ZFS="false"
fi

# Copy the Samba source tree into the VM (skip VCS + build artifacts).
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
ssh debian@$VM_IP bash -s "$CACHED_ZFS" "$ZFS_BRANCH" <<'REMOTE_SCRIPT'
CACHED_ZFS="$1"
ZFS_BRANCH="$2"
set -eu
export DEBIAN_FRONTEND=noninteractive

sudo apt-get update

##################################################################
# 1. TrueNAS OpenZFS: kmod + userland (provides libzfs7 / -devel,
#    libnvpair3, libuutil3, libzpool... that Samba builds against).
##################################################################
if [ -d "/tmp/zfs-debs" ] && ls /tmp/zfs-debs/*.deb >/dev/null 2>&1; then
  echo "Using cached OpenZFS packages..."
  sudo apt-get -y install $(find /tmp/zfs-debs -name '*.deb' | grep -Ev 'dkms|dracut')
  sudo depmod -a
else
  echo "Building OpenZFS ($ZFS_BRANCH) from source..."
  sudo apt-get install -y \
    build-essential autoconf automake libtool gawk alien fakeroot dkms \
    libblkid-dev uuid-dev libudev-dev libssl-dev zlib1g-dev libaio-dev \
    libattr1-dev libelf-dev "linux-headers-$(uname -r)" python3 \
    python3-dev python3-setuptools python3-cffi python3-packaging \
    python3-distlib libffi-dev git \
    libtirpc-dev \
    dh-python libpam0g-dev python3-all-dev python3-sphinx
  cd /tmp
  git clone --depth 1 --branch "$ZFS_BRANCH" https://github.com/truenas/zfs.git
  cd zfs
  ./autogen.sh
  ./configure --prefix=/usr --enable-pyzfs --enable-debuginfo
  make -j"$(nproc)" native-deb-kmod native-deb-utils

  echo "Caching built ZFS packages..."
  mkdir -p /tmp/zfs-debs
  find /tmp -maxdepth 1 -name '*.deb' | grep -Ev 'dkms|dracut' | while read -r deb; do
    cp "$deb" /tmp/zfs-debs/
  done

  sudo apt-get -y install $(find /tmp -maxdepth 1 -name '*.deb' | grep -Ev 'dkms|dracut')
  sudo depmod -a
fi

# The kmod must target the *running* kernel, else modprobe fails silently
# after the reboot. Fail loudly here instead.
KVER="$(uname -r)"
ZFS_KO="$(find "/lib/modules/$KVER" -name 'zfs.ko*' -print -quit 2>/dev/null || true)"
if [ -z "$ZFS_KO" ]; then
  echo "FATAL: no zfs.ko under /lib/modules/$KVER/"
  find /lib/modules -name 'zfs.ko*' 2>/dev/null || echo "  (none found)"
  exit 1
fi
echo "Found zfs.ko at: $ZFS_KO"

# Confirm the libzfs dev headers Samba needs are now present.
echo "Installed ZFS userland packages:"
dpkg -l | grep -Ei 'libzfs|libnvpair|libuutil|libzpool' || true

##################################################################
# 2. Samba build dependencies. The libzfs7 / libzfs7-devel /
#    libnvpair3 / libuutil3 Build-Depends are satisfied by the ZFS
#    debs installed above; apt-get build-dep pulls the rest.
##################################################################
echo "Installing Samba build dependencies..."
cd ~/samba
sudo apt-get install -y build-essential devscripts equivs ccache
# build-dep reads debian/control; the openzfs-* packages installed above
# satisfy libzfs7 / libzfs7-devel / libnvpair3 / libuutil3 via their
# Debian "Provides:" (the package names differ; the virtual names match).
sudo apt-get build-dep -y . || {
  echo "apt-get build-dep failed; retrying via mk-build-deps..."
  sudo mk-build-deps --install --remove \
    --tool='apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y' \
    debian/control
}

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
# 3. Build Samba (waf via dpkg-buildpackage, configured --with-libzfs).
##################################################################
echo "Building Samba (this is the long pole)..."
cd ~/samba
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
# 4. Verify the TrueNAS VFS modules were built + packaged.
##################################################################
echo "Verifying TrueNAS VFS modules are present..."
VFS_DIR="$(dirname "$(find /usr/lib -path '*/samba/vfs/zfs_core.so' -print -quit)")"
echo "VFS module dir: ${VFS_DIR:-<not found>}"
MISSING=0
for m in truenas_streams_xattr zfs_core ixnas tmprotect shadow_copy_zfs truenas_audit; do
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
REMOTE_SCRIPT

# Pull freshly-built ZFS debs back to the host for caching (before poweroff).
if [ "$CACHED_ZFS" = "false" ]; then
  echo "Copying built OpenZFS packages from VM for caching..."
  mkdir -p /tmp/zfs-debs
  rsync -az debian@$VM_IP:/tmp/zfs-debs/ /tmp/zfs-debs/ || echo "Note: nothing to cache"
fi

# Pull the updated ccache back to the host so actions/cache can save it.
echo "Saving ccache from VM for caching..."
mkdir -p /tmp/ccache
rsync -az debian@$VM_IP:~/.ccache/ /tmp/ccache/ || echo "Note: no ccache to save"

# Reboot is required so the ZFS kmod loads cleanly for the test stage.
echo "Cleaning cloud-init and powering off VM..."
ssh debian@$VM_IP 'sudo cloud-init clean --logs && sync && sleep 2 && sudo poweroff' &

echo "Build complete; VM shutting down for restart"
