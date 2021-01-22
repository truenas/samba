The packaging is kept in https://salsa.debian.org/samba-team/samba.

The version in unstable is on the `master` branch, with the corresponding
upstream version in the `upstream_4.13` branch (with `pristine-tar` information
in the `pristine-tar` branch).

It should be possible to build the package by just running `gbp buildpackage`.

Building
========

The first time:

    sudo apt install git-buildpackage pristine-tar cowbuilder
    DIST=sid ARCH=amd64 git-pbuilder create
    git clone https://salsa.debian.org/samba-team/samba.git

Each time:

    cd samba
    git checkout master
    gbp pull --track-missing
    gbp buildpackage --git-pbuilder --git-dist=sid --git-arch=amd64

Merging minor upstream releases
===============================

Importing a new upstream version can be done like this:

    # set target version
    upstream_version=4.13.3
    # go to git repo
    cd $GIT_DIR
    # Import upstream
    git remote add upstream https://git.samba.org/samba.git
    git fetch upstream
    # go to the Debian branch
    git checkout master
    # sync all required branches
    gbp pull --track-missing
    # Import latest version
    gbp import-orig --uscan \
      -u "${upstream_version}+dfsg" \
      --upstream-vcs-tag "samba-${upstream_version}" \
      --merge-mode merge
    # all done :)


Please note that there are some files that are not dfsg-free and they need to
be filtered. The settings in the `gpb.conf` configuration file should take
care of that.

Merging major upstream releases
===============================

With a new major version, more work is needed.

After `gbp pull`:

    major_version="$(echo $upstream_version | sed 's/.[^.]\+$//')"
    # Edit gbp.conf's upstream-branch
    editor debian/gbp.conf
    # Edit debian/watch's major version
    editor debian/watch
    # Edit this file's major version
    editor debian/README.source
    # Commit
    git commit -m"Update d/gbp.conf, d/watch and d/README.source for ${major_version}" debian/gbp.conf debian/watch debian/README.source.md
    # Create the new upstream branch
    git branch "upstream_${major_version}" samba-${upstream_version}
    # Import latest version
    gbp import-orig --uscan \
      -u "${upstream_version}+dfsg" \
      --upstream-vcs-tag "samba-${upstream_version}" \
      --merge-mode=replace

Then several steps are needed:

- Apply all patches:

        git am $(cat debian/patches/series | sed s@^@debian/patches/@)
        # then update or drop patches as needed

- Bump talloc, tdb, tevent and ldb Build-Depends in debian/control, from lib/*/wscript

        grep ^VERSION lib/{talloc,tdb,tevent,ldb}/wscript
        editor debian/control

- Check if other Build-Depends need to be bumped

        git diff origin/master.."samba-${upstream_version}" \
        buildtools/wafsamba/samba_third_party.py
