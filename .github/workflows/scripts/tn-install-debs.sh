#!/usr/bin/env bash

######################################################################
# Install the debs of a CI run in the VM, as the user debian.
# qemu-3-build.sh and qemu-3-install.sh run it.
#
#   tn-install-debs.sh kernel KERNEL_DIR ZFS_DIR
#   tn-install-debs.sh samba DEB...
#   tn-install-debs.sh only-truenas-kernel KERNEL_DIR
#
# KERNEL_DIR and ZFS_DIR are download directories of tn-fetch-debs.sh,
# with their manifest.json.
#
# kernel: installs the TrueNAS kernel image, its UAPI headers and the
#   OpenZFS debs, and checks that zfs.ko is under the modules of that
#   kernel.
# samba: installs truenas-samba and checks that the TrueNAS VFS modules
#   are present.
# only-truenas-kernel: removes the distribution kernels. The next boot
#   then uses the TrueNAS kernel, and the prebuilt zfs.ko can load.
######################################################################

set -eu
export DEBIAN_FRONTEND=noninteractive

# The release of the TrueNAS kernel in KERNEL_DIR $1
kernel_release() {
  jq -r '.release' "$1/manifest.json"
}

install_kernel() {
  local kdir="$1" zdir="$2" release zfs_krel zfs_ko

  # The OpenZFS kmod is built against one exact kernel.  The kernel and zfs
  # nightlies roll independently, so if the kernel has advanced past the one
  # zfs was built against, the prebuilt zfs.ko will not load.  Refuse to
  # proceed on a mismatch with a clear message rather than failing later at
  # modprobe time.
  release="$(kernel_release "$kdir")"
  zfs_krel="$(jq -r '.kernel_release' "$zdir/manifest.json")"
  if [ "$zfs_krel" != "$release" ]; then
    echo "FATAL: the OpenZFS nightly debs were built against kernel $zfs_krel,"
    echo "but the truenas/linux nightly currently publishes kernel $release."
    echo "The two rolling nightlies are out of sync; the prebuilt zfs.ko cannot"
    echo "load under the mismatched kernel.  This self-heals once the truenas/zfs"
    echo "nightly rebuilds against $release."
    exit 1
  fi
  echo "Kernel release: $release (matches the OpenZFS build kernel)"

  # Install the kernel image first so /lib/modules/$release exists and the
  # OpenZFS modules deb's linux-image dependency resolves; the libc-dev
  # package Provides/Conflicts the stock linux-libc-dev, so it replaces it.
  echo "Installing TrueNAS kernel image + UAPI headers..."
  sudo -E apt-get install -y \
    "$kdir"/linux-image-*.deb \
    "$kdir"/linux-*libc-dev_*.deb

  # Install the OpenZFS userland + kmod debs (the release already excludes
  # dkms/dracut).  These provide the libzfs7 / libzfs7-devel / libnvpair3 /
  # libuutil3 that Samba's Build-Depends name (the package names differ; the
  # virtual names they Provide match).
  echo "Installing OpenZFS debs..."
  sudo -E apt-get install -y "$zdir"/openzfs-*.deb
  sudo depmod -a "$release"

  # The prebuilt zfs.ko must have landed under the TrueNAS kernel's modules
  # tree, or the post-reboot modprobe will fail.  Fail loudly here instead.
  zfs_ko="$(find "/lib/modules/$release" -name 'zfs.ko*' -print -quit 2>/dev/null || true)"
  if [ -z "$zfs_ko" ]; then
    echo "FATAL: no zfs.ko under /lib/modules/$release/ after installing the OpenZFS modules deb"
    echo "Installed zfs.ko paths in /lib/modules:"
    find /lib/modules -name 'zfs.ko*' 2>/dev/null || echo "  (none found)"
    exit 1
  fi
  echo "Found zfs.ko at: $zfs_ko"

  echo "Installed ZFS userland packages:"
  dpkg -l | grep -Ei 'libzfs|libnvpair|libuutil|libzpool' || true
}

install_samba() {
  local vfs_dir missing=0 m

  echo "Installing truenas-samba..."
  sudo -E apt-get install -y "$@" || {
    sudo dpkg -i "$@" || true
    sudo -E apt-get install -f -y
  }

  echo "Verifying TrueNAS VFS modules are present..."
  vfs_dir="$(dirname "$(find /usr/lib -path '*/samba/vfs/zfs_core.so' -print -quit)")"
  echo "VFS module dir: ${vfs_dir:-<not found>}"
  # io_uring is in the list because it is the module that proves the pinned
  # upstream liburing was found: source3/wscript only adds vfs_io_uring to the
  # default module set when configure detected liburing.
  for m in truenas_streams_xattr zfs_core ixnas tmprotect shadow_copy_zfs truenas_audit io_uring; do
    if [ -n "${vfs_dir:-}" ] && [ -e "$vfs_dir/$m.so" ]; then
      echo "  ok   $m.so"
    else
      echo "  MISS $m.so"
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ]; then
    echo "FATAL: one or more expected TrueNAS VFS modules are missing"
    ls -l "${vfs_dir:-/usr/lib}" || true
    exit 1
  fi
  echo "All expected TrueNAS VFS modules built and installed."
}

only_truenas_kernel() {
  local release stock

  release="$(kernel_release "$1")"
  echo "Removing distribution kernels so the TrueNAS kernel is the default..."
  # Let apt remove the running (stock) kernel without aborting.
  echo 'linux-base linux-base/removing-running-kernel boolean false' | \
    sudo debconf-set-selections
  # TrueNAS kernel packages carry version-free names
  # (linux-{image,headers}-truenas-production-amd64), so tell them apart from
  # the distribution kernels by name.
  stock=$(dpkg-query -W -f '${Package}\n' 'linux-image-*' 'linux-headers-*' | \
    grep -v -- truenas || true)
  if [ -n "$stock" ]; then
    # shellcheck disable=SC2086
    sudo -E apt-get purge -y $stock
  fi
  sudo update-grub

  # The TrueNAS kernel must now be the one and only installed kernel.
  test -e "/boot/vmlinuz-$release"
  test "$(ls /boot/vmlinuz-* | wc -l)" -eq 1
  echo "TrueNAS kernel $release is the only installed kernel."
}

case "${1:-}" in
kernel)
  install_kernel "${2:?KERNEL_DIR}" "${3:?ZFS_DIR}" ;;
samba)
  shift
  [ $# -gt 0 ] || { echo "usage: tn-install-debs.sh samba DEB..."; exit 2; }
  install_samba "$@" ;;
only-truenas-kernel)
  only_truenas_kernel "${2:?KERNEL_DIR}" ;;
*)
  echo "usage: tn-install-debs.sh kernel KERNEL_DIR ZFS_DIR | samba DEB... |"
  echo "       only-truenas-kernel KERNEL_DIR"
  exit 2 ;;
esac
