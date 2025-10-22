#ifndef PYCLIENT_TABLES_H
#define PYCLIENT_TABLES_H
#include pyclient.h

/*
 * We will use intlags_enum_entry_t to construct python enum.IntFlag enum
 * instances on module load and store them in our module state as well as
 * having object references at root of module itself.
 */
typedef struct { uint32_t val; const char *name; } intflags_enum_entry_t;

/*
 * Lookup table to create pyctdb.NodeFlags IntFlags enum
 * These are defined in protocol/protocol.h
 *
 * NODE_FLAGS_DISABLED and NODE_FLAGS_INACTIVE are handled during enum
 * construction.
 */
static const intflags_enum_entry_t node_flags_tbl[] = {
	/* 0x00000001 -- node isn't connected */
	{ NODE_FLAGS_DISCONNECTED, "DISCONNECTED" },
	/* 0x00000002 -- monitoring says node is unhealthy */
	{ NODE_FLAGS_UNHEALTHY, "UNHEALTHY" },
	/* 0x00000004 -- administrator has disabled node */
	{ NODE_FLAGS_PERMANENTLY_DISABLED, "PERMANENTLY_DISABLED" },
	/* 0x00000008 -- recovery daemon has banned the node */
	{ NODE_FLAGS_BANNED, "BANNED" },
	/* 0x00000010 -- this node has been deleted */
	{ NODE_FLAGS_DELETED, "DELETED" },
	/* 0x00000020 -- this node has been stopped */
	{ NODE_FLAGS_STOPPED, "STOPPED" },
};

_Static_assert(
	NODE_FLAGS_LAST == node_flags_tbl[ARRAY_SIZE(node_flags_tbl) - 1].val,
	"pyctdb node flags table needs to be updated"
);

/* Lookup table to create pyctdb.CtdbDbFlags python enum.IntFlag enum */
static const intflags_enum_entry_t db_flags_tbl[] = {
	{ CTDB_DB_FLAGS_PERSISTENT, "PERSISTENT" },	/* 0x01 */
	{ CTDB_DB_FLAGS_READONLY, "READONLY" },		/* 0x02 */
	{ CTDB_DB_FLAGS_STICKY, "STICKY" },		/* 0x04 */
	{ CTDB_DB_FLAGS_REPLICATED, "REPLICATED" },	/* 0x08 */
};

_Static_assert(
	CTDB_DB_FLAGS_LAST == db_flags_tbl[ARRAY_SIZE(db_flags_tbl) - 1].val,
	"pyctdb db flags table needs to be updated"
);

/*
 * pyctdb.CapFlags python enum.IntFlag enum basis
 * These are defined in protocol/protocol.h
 *
 * CTBD_CAP_FEATURES and CTDB_CAP_DEFAULT will be defined when creating the
 * actual enum and inserted as an object reference in module.
 */
static const intflags_enum_entry_t cap_flags_tbl[] = {
	{ CTDB_CAP_RECMASTER, "RECMASTER" },
	{ CTDB_CAP_LMASTER, "LMASTER" },
	{ CTDB_CAP_LVS, "LVS" },		/* obsolete */
	{ CTDB_CAP_NATGW, "NATGW" },		/* obsolete */
	{ CTDB_CAP_PARALLEL_RECOVERY, "PARALLEL_RECOVERY" },
	{ CTDB_CAP_FRAGMENTED_CONTROLS, "FRAGMENTED_CONTROLS" },
};

_Static_assert(
	CTDB_CAP_LAST == cap_flags_tbl[ARRAY_SIZE(cap_flags_tbl) - 1].val,
	"pyctdb CTDB cap flags table needs to be updated"
);

#endif /* PYCLIENT_TABLES_H */
