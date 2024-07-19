/* Copyright (C) 1995-1998 Samba-Team */
/* Copyright (C) 1998 John H Terpstra <jht@aquasoft.com.au> */

/* local definitions for file server */
#ifndef _LOCAL_H
#define _LOCAL_H

/* Yves Gaige <yvesg@hptnodur.grenoble.hp.com> requested this set this 	     */
/* to a maximum of 8 if old smb clients break because of long printer names. */
#define MAXPRINTERLEN 15

/* max number of SMB1 directory handles */
/* As this now uses the bitmap code this can be
   quite large. */
#define MAX_DIRECTORY_HANDLES 2048

/* maximum number of file caches per smbd */
#define MAX_WRITE_CACHES 10

/*
 * Fudgefactor required for open tdb's, etc.
 */

#ifndef MAX_OPEN_FUDGEFACTOR
#define MAX_OPEN_FUDGEFACTOR 40
#endif

/*
 * Minimum number of open files needed for Windows7 to
 * work correctly. A little conservative but better that
 * than run out of fd's.
 */

#ifndef MIN_OPEN_FILES_WINDOWS
#define MIN_OPEN_FILES_WINDOWS 16384
#endif

/*
 * Default number of maximum open files per smbd. This is
 * also limited by the maximum available file descriptors
 * per process and can also be set in smb.conf as "max open files"
 * in the [global] section.
 */

#ifndef MAX_OPEN_FILES
#define MAX_OPEN_FILES (MIN_OPEN_FILES_WINDOWS + MAX_OPEN_FUDGEFACTOR)
#endif

#define WORDMAX 0xFFFF

/* the maximum password length before we declare a likely attack */
#define MAX_PASS_LEN 200

/* separators for lists */
#define LIST_SEP " \t,;\n\r"

/* wchar separators for lists */
#define LIST_SEP_W wchar_list_sep

/* this is where browse lists are kept in the lock dir */
#define SERVER_LIST "browse.dat"

/* shall filenames with illegal chars in them get mangled in long
   filename listings? */
#define MANGLE_LONG_FILENAMES 

/* define this if you want to stop spoofing with .. and soft links
   NOTE: This also slows down the server considerably */
#define REDUCE_PATHS

/* the size of the directory cache */
#define DIRCACHESIZE 20

/* what default type of filesystem do we want this to show up as in a
   NT file manager window? */
#define FSTYPE_STRING "NTFS"

/* user to test password server with as invalid in security=server mode. */
#ifndef INVALID_USER_PREFIX
#define INVALID_USER_PREFIX "sambatest"
#endif

/* the default pager to use for the client "more" command. Users can
   override this with the PAGER environment variable */
#ifndef PAGER
#define PAGER "more"
#endif

/* the size of the uid cache used to reduce valid user checks */
#define VUID_CACHE_SIZE 32

/* the following control timings of various actions. Don't change 
   them unless you know what you are doing. These are all in seconds */
#define SMBD_RELOAD_CHECK (180)
#define IDLE_CLOSED_TIMEOUT (60)
#define SMBD_SELECT_TIMEOUT (60)
#define NMBD_SELECT_LOOP (10)
#define BROWSE_INTERVAL (60)
#define REGISTRATION_INTERVAL (10*60)
#define NMBD_INETD_TIMEOUT (120)
#define NMBD_MAX_TTL (24*60*60)
#define LPQ_LOCK_TIMEOUT (5)
#define NMBD_INTERFACES_RELOAD (120)
#define NMBD_UNEXPECTED_TIMEOUT (15)
#define SMBD_HOUSEKEEPING_INTERVAL SMBD_SELECT_TIMEOUT

/* the following are in milliseconds */
#define LOCK_RETRY_TIMEOUT (100)

/* do you want to dump core (carefully!) when an internal error is
   encountered? Samba will be careful to make the core file only
   accessible to root */
#define DUMP_CORE 1

/* shall we support browse requests via a FIFO to nmbd? */
#define ENABLE_FIFO 1

/* how long (in milliseconds) to wait for a socket connect to happen */
#define LONG_CONNECT_TIMEOUT 30000
#define SHORT_CONNECT_TIMEOUT 5000

/* the default netbios keepalive timeout */
#define DEFAULT_KEEPALIVE 300

/* the directory to sit in when idle */
/* #define IDLE_DIR "/" */

/* Timeout (in seconds) to wait for an oplock break
   message to return from the client. */

#define OPLOCK_BREAK_TIMEOUT 35

/* Timeout (in seconds) to add to the oplock break timeout
   to wait for the smbd to smbd message to return. */

#define OPLOCK_BREAK_TIMEOUT_FUDGEFACTOR 2

/* the read preciction code has been disabled until some problems with
   it are worked out */
#define USE_READ_PREDICTION 0

/* Minimum length of allowed password when changing UNIX password. */
#define MINPASSWDLENGTH 5

/* the maximum age in seconds of a password. Should be a lp_ parameter */
#define MAX_PASSWORD_AGE (21*24*60*60)

/* shall we deny oplocks to clients that get timeouts? */
#define FASCIST_OPLOCK_BACKOFF 1

/* this enables the "rabbit pellet" fix for SMBwritebraw */
#define RABBIT_PELLET_FIX 1

/* Max number of open RPC pipes. */
#define MAX_OPEN_PIPES 2048

/* Tuning for server auth mutex. */
#define CLI_AUTH_TIMEOUT 5000 /* In milli-seconds. */
#define NUM_CLI_AUTH_CONNECT_RETRIES 3
/* Number in seconds to wait for the mutex. This must be less than 30 seconds. */
#define SERVER_MUTEX_WAIT_TIME ( ((NUM_CLI_AUTH_CONNECT_RETRIES) * ((CLI_AUTH_TIMEOUT)/1000)) + 5)
/* Number in seconds for winbindd to wait for the mutex. Make this 2 * smbd wait time. */
#define WINBIND_SERVER_MUTEX_WAIT_TIME (( ((NUM_CLI_AUTH_CONNECT_RETRIES) * ((CLI_AUTH_TIMEOUT)/1000)) + 5)*2)

/* size of listen() backlog in smbd */
#if defined (FREEBSD)
#define SMBD_LISTEN_BACKLOG -1
#else
#define SMBD_LISTEN_BACKLOG 50
#endif

/* size of listen() default backlog */
#if defined (FREEBSD)
#define DEFAULT_LISTEN_BACKLOG -1
#else
#define DEFAULT_LISTEN_BACKLOG 5
#endif

/* Number of microseconds to wait before a sharing violation. */
#define SHARING_VIOLATION_USEC_WAIT 950000

/* Number of microseconds to wait before a updating the write time (2 secs). */
#define WRITE_TIME_UPDATE_USEC_DELAY 2000000

#define MAX_LDAP_REPLICATION_SLEEP_TIME 5000 /* In milliseconds. */

/* tdb hash size for the databases having one entry per open file. */
#define SMBD_VOLATILE_TDB_HASH_SIZE 10007

/* tdb flags for the databases having one entry per open file. */
#define SMBD_VOLATILE_TDB_FLAGS \
	(TDB_DEFAULT|TDB_VOLATILE|TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH)

/* Characters we disallow in sharenames. */
#define INVALID_SHARENAME_CHARS "%<>*?|/\\+=;:\","

/* Seconds between connection attempts to a remote server. */
#define FAILED_CONNECTION_CACHE_TIMEOUT (LONG_CONNECT_TIMEOUT * 2 / 1000)

/* Default hash size for the winbindd cache. */
#define WINBINDD_CACHE_TDB_DEFAULT_HASH_SIZE 5000

/* Windows minimum lock resolution timeout in ms */
#define WINDOWS_MINIMUM_LOCK_TIMEOUT_MS 200

/* Maximum size of RPC data we will accept for one call. */
#define MAX_RPC_DATA_SIZE (15*1024*1024)

/* A guestimate of how many domains winbindd will be contacting */
#ifndef WINBIND_MAX_DOMAINS_HINT
#define WINBIND_MAX_DOMAINS_HINT 10
#endif
#endif
