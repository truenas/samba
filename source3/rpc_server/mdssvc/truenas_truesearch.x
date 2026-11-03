/*
 * truenas_truesearch wire protocol, version 1.
 *
 * XDR (RFC 4506). Every message on the socket is one record: a 4-byte
 * big-endian length that does not count itself, followed by exactly that
 * many bytes of XDR, which decode as one rix_call (client to daemon) or one
 * rix_reply (daemon to client). Strings are UTF-8 in NFC.
 *
 * A share is named by where it is, not by how its path is spelled: the
 * dataset of the filesystem it is on (the mount's source, e.g. "tank/data")
 * and the path of its root within that filesystem. Every other path is
 * relative to the share's root. A relative path has no slash at either end
 * and no empty, "." or ".." component; "" is the share's root.
 *
 * The Rust side encodes and decodes with truenas_xdr (serde, byte-exact,
 * Strictness::Strict). The Samba side uses libtirpc's xdrmem_* on a buffer.
 * A decoder that meets a version it does not know refuses the message.
 *
 * The version field is spelled `vers`: `version` is a keyword of the RPC
 * language, and rpcgen, which generates the Samba side's codec from this
 * file, refuses it as a field name.
 */

const RIX_PROTO_VERSION = 1;

/* Declared maxima. A message past any of them is refused, not truncated. */
const RIX_MAX_QUERY   = 4096;   /* bytes of Spotlight query text            */
const RIX_MAX_PATH    = 4096;   /* bytes of one path                        */
const RIX_MAX_GROUPS  = 8192;   /* supplementary groups in one identity     */
const RIX_MAX_CNIDS   = 4096;   /* item IDs a query may be limited to       */
const RIX_MAX_PAGE    = 1000;   /* hits in one page                         */
const RIX_MAX_RESULTS = 1000;   /* hits one query computes                  */
const RIX_MAX_DETAIL  = 256;    /* bytes of error detail                    */
const RIX_MAX_FRAME   = 16777216; /* bytes in one record, either direction  */

enum rix_op {
    RIX_HELLO = 0,
    RIX_OPEN  = 1,
    RIX_FETCH = 2,
    RIX_CLOSE = 3
};

/*
 * Who is asking. Taken from Samba's session token (unix_token: uid, gid,
 * groups), which carries directory-service groups exactly. The daemon
 * honours an identity only when the peer's SO_PEERCRED uid is 0; any other
 * peer is given its own peercred identity whatever it asserts.
 */
struct rix_identity {
    unsigned int uid;
    unsigned int gid;
    unsigned int gids<RIX_MAX_GROUPS>;
};

/* rix_open.flags */
const RIX_OPEN_TRIM_BY_IDENTITY = 1;  /* drop hits the identity could not   */
                                      /* find by browsing the share         */
const RIX_OPEN_WANT_STAT        = 2;  /* return rix_stat with every hit     */
const RIX_OPEN_HIDE_UNREADABLE  = 4;  /* with the trim, drop hits it may    */
                                      /* not open for reading, as the       */
                                      /* share's access-based enumeration   */
                                      /* hides them from a listing          */

struct rix_hello {
    unsigned int vers;                /* the client's RIX_PROTO_VERSION     */
};

struct rix_open {
    string dataset<RIX_MAX_PATH>;     /* the dataset of the share's root      */
    string share<RIX_MAX_PATH>;       /* the share's root within the dataset; */
                                      /* "" is the dataset's root             */
    string scope<RIX_MAX_PATH>;       /* directory under the share's root     */
    string query<RIX_MAX_QUERY>;      /* raw Spotlight query, Apple's syntax  */
    rix_identity who;
    unsigned int flags;
    unsigned int max_results;         /* 1..RIX_MAX_RESULTS; 0 = the maximum  */
    unsigned hyper cnids<RIX_MAX_CNIDS>; /* restrict to these item IDs, each a       */
                                         /* rix_smb_qfid.file_id; empty = all        */
};

struct rix_fetch {
    unsigned hyper handle;
    unsigned int limit;               /* 1..RIX_MAX_PAGE; 0 = the maximum     */
};

struct rix_close {
    unsigned hyper handle;
};

union rix_request switch (rix_op op) {
case RIX_HELLO: rix_hello hello;
case RIX_OPEN:  rix_open  open;
case RIX_FETCH: rix_fetch fetch;
case RIX_CLOSE: rix_close close;
};

struct rix_call {
    unsigned int vers;                /* RIX_PROTO_VERSION                    */
    unsigned int xid;                 /* echoed in the reply                  */
    rix_request request;
};

enum rix_status {
    RIX_OK          = 0,
    RIX_BAD_VERSION = 1,  /* unknown protocol version                        */
    RIX_BAD_QUERY   = 2,  /* the query text does not parse, or names an      */
                          /* attribute or function the daemon does not serve */
    RIX_BAD_SCOPE   = 3,  /* scope is not a directory under the share        */
    RIX_NO_INDEX    = 4,  /* no index target holds the share                 */
    RIX_DENIED      = 5,  /* identity asserted by a non-root peer            */
    RIX_BAD_HANDLE  = 6,  /* unknown, closed, or expired handle              */
    RIX_BUSY        = 7,  /* the daemon shed the query; retry later          */
    RIX_INTERNAL    = 8
};

/*
 * The SMB identity of a file, as smbd gives it with vfs_zfs_core.
 *
 * file_id is the MS-FSCC FileId and the Spotlight item ID. Every hit is
 * on the share's dataset, where it is (gen mod 2^24) << 40 | 1 << 39 |
 * ino, as in Samba's zfs_core_file_id.h. It is ino when gen is 0 or ino
 * does not fit in 39 bits. A Mac uses it as the inode number of the file
 * and sends it back in kMDQueryItemArray.
 *
 * volume_id is the fsid of the dataset (statfs f_fsid, val[1] << 32 |
 * val[0]), as smbd gives it in the QFid create context. ZFS keeps it in
 * the pool, so it is the same after a reboot and a failover. A device
 * number is not.
 */
struct rix_smb_qfid {
    unsigned hyper file_id;
    unsigned hyper volume_id;
};

/*
 * The unix identity of a file. ino and gen make ZFS's file handle; with
 * volume_id, they are the file system's part of an NFS file handle.
 */
struct rix_unix_meta {
    unsigned hyper ino;               /* object number                    */
    unsigned int   gen;               /* inode generation, low 32 bits    */
    unsigned int   uid;
    unsigned int   gid;
    unsigned int   mode;
};

/* What the Spotlight item ID and Samba's add_filemeta need. */
struct rix_stat {
    rix_smb_qfid   qfid;
    rix_unix_meta  unix_meta;         /* not "unix": GNU C defines it     */
    unsigned hyper size;
    hyper          mtime_sec;
    unsigned int   mtime_nsec;
    hyper          btime_sec;
    unsigned int   btime_nsec;
    hyper          atime_sec;
    unsigned int   atime_nsec;
};

struct rix_hit {
    string   path<RIX_MAX_PATH>;      /* relative to the share's root         */
    rix_stat *st;                     /* present when RIX_OPEN_WANT_STAT      */
};

struct rix_welcome {
    unsigned int vers;                /* the daemon's RIX_PROTO_VERSION       */
    unsigned int max_results;         /* RIX_MAX_RESULTS as configured        */
    unsigned int max_page;            /* RIX_MAX_PAGE as configured           */
    unsigned int handle_idle_seconds; /* a handle unfetched this long expires */
};

struct rix_opened {
    unsigned hyper handle;
    unsigned int   ready;             /* hits computed, after scope, filters  */
                                      /* and trimming; at most max_results    */
    bool           truncated;         /* more matched than max_results        */
};

struct rix_page {
    rix_hit hits<RIX_MAX_PAGE>;
    bool    more;                     /* another fetch would return hits      */
};

union rix_answer switch (rix_op op) {
case RIX_HELLO: rix_welcome welcome;
case RIX_OPEN:  rix_opened  opened;
case RIX_FETCH: rix_page    page;
case RIX_CLOSE: void;
};

union rix_outcome switch (rix_status status) {
case RIX_OK: rix_answer answer;
default:     string detail<RIX_MAX_DETAIL>;
};

struct rix_reply {
    unsigned int vers;
    unsigned int xid;
    rix_outcome  outcome;
};
