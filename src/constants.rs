// SPDX-License-Identifier: MIT

//! Define constants related to generic netlink
pub const GENL_ID_CTRL: u16 = 16;
pub const GENL_ID_DEVLINK: u16 = 23;
pub const GENL_HDRLEN: usize = 4;

pub const CTRL_CMD_UNSPEC: u8 = 0;
pub const CTRL_CMD_NEWFAMILY: u8 = 1;
pub const CTRL_CMD_DELFAMILY: u8 = 2;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_CMD_NEWOPS: u8 = 4;
pub const CTRL_CMD_DELOPS: u8 = 5;
pub const CTRL_CMD_GETOPS: u8 = 6;
pub const CTRL_CMD_NEWMCAST_GRP: u8 = 7;
pub const CTRL_CMD_DELMCAST_GRP: u8 = 8;
pub const CTRL_CMD_GETMCAST_GRP: u8 = 9;
pub const CTRL_CMD_GETPOLICY: u8 = 10;

pub const CTRL_ATTR_UNSPEC: u16 = 0;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_VERSION: u16 = 3;
pub const CTRL_ATTR_HDRSIZE: u16 = 4;
pub const CTRL_ATTR_MAXATTR: u16 = 5;
pub const CTRL_ATTR_OPS: u16 = 6;
pub const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
pub const CTRL_ATTR_POLICY: u16 = 8;
pub const CTRL_ATTR_OP_POLICY: u16 = 9;
pub const CTRL_ATTR_OP: u16 = 10;

pub const CTRL_ATTR_OP_UNSPEC: u16 = 0;
pub const CTRL_ATTR_OP_ID: u16 = 1;
pub const CTRL_ATTR_OP_FLAGS: u16 = 2;

pub const CTRL_ATTR_MCAST_GRP_UNSPEC: u16 = 0;
pub const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
pub const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

pub const CTRL_ATTR_POLICY_UNSPEC: u16 = 0;
pub const CTRL_ATTR_POLICY_DO: u16 = 1;
pub const CTRL_ATTR_POLICY_DUMP: u16 = 2;

pub const NL_ATTR_TYPE_INVALID: u32 = 0;
pub const NL_ATTR_TYPE_FLAG: u32 = 1;
pub const NL_ATTR_TYPE_U8: u32 = 2;
pub const NL_ATTR_TYPE_U16: u32 = 3;
pub const NL_ATTR_TYPE_U32: u32 = 4;
pub const NL_ATTR_TYPE_U64: u32 = 5;
pub const NL_ATTR_TYPE_S8: u32 = 6;
pub const NL_ATTR_TYPE_S16: u32 = 7;
pub const NL_ATTR_TYPE_S32: u32 = 8;
pub const NL_ATTR_TYPE_S64: u32 = 9;
pub const NL_ATTR_TYPE_BINARY: u32 = 10;
pub const NL_ATTR_TYPE_STRING: u32 = 11;
pub const NL_ATTR_TYPE_NUL_STRING: u32 = 12;
pub const NL_ATTR_TYPE_NESTED: u32 = 13;
pub const NL_ATTR_TYPE_NESTED_ARRAY: u32 = 14;
pub const NL_ATTR_TYPE_BITFIELD32: u32 = 15;

pub const NL_POLICY_TYPE_ATTR_UNSPEC: u16 = 0;
pub const NL_POLICY_TYPE_ATTR_TYPE: u16 = 1;
pub const NL_POLICY_TYPE_ATTR_MIN_VALUE_S: u16 = 2;
pub const NL_POLICY_TYPE_ATTR_MAX_VALUE_S: u16 = 3;
pub const NL_POLICY_TYPE_ATTR_MIN_VALUE_U: u16 = 4;
pub const NL_POLICY_TYPE_ATTR_MAX_VALUE_U: u16 = 5;
pub const NL_POLICY_TYPE_ATTR_MIN_LENGTH: u16 = 6;
pub const NL_POLICY_TYPE_ATTR_MAX_LENGTH: u16 = 7;
pub const NL_POLICY_TYPE_ATTR_POLICY_IDX: u16 = 8;
pub const NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE: u16 = 9;
pub const NL_POLICY_TYPE_ATTR_BITFIELD32_MASK: u16 = 10;
pub const NL_POLICY_TYPE_ATTR_PAD: u16 = 11;
pub const NL_POLICY_TYPE_ATTR_MASK: u16 = 12;

/// Devlink commands
/// 
pub const DEVLINK_CMD_GET: u8 = 1;		/* can dump */
pub const DEVLINK_CMD_SET: u8 = 2;
pub const DEVLINK_CMD_NEW: u8 = 3;
pub const DEVLINK_CMD_DEL: u8 = 4;

pub const DEVLINK_CMD_PORT_GET: u8 = 5;		/* can dump */
pub const DEVLINK_CMD_PORT_SET: u8 = 6;
pub const DEVLINK_CMD_PORT_NEW: u8 = 7;
pub const DEVLINK_CMD_PORT_DEL: u8 = 8;

pub const DEVLINK_CMD_PORT_SPLIT: u8 = 9;
pub const DEVLINK_CMD_PORT_UNSPLIT: u8 = 10;

pub const DEVLINK_CMD_SB_GET: u8 = 11;		/* can dump */
pub const DEVLINK_CMD_SB_SET: u8 = 12;
pub const DEVLINK_CMD_SB_NEW: u8 = 13;
pub const DEVLINK_CMD_SB_DEL: u8 = 14;

pub const DEVLINK_CMD_SB_POOL_GET: u8 = 15;	/* can dump */
pub const DEVLINK_CMD_SB_POOL_SET: u8 = 16;
pub const DEVLINK_CMD_SB_POOL_NEW: u8 = 17;
pub const DEVLINK_CMD_SB_POOL_DEL: u8 = 18;

pub const DEVLINK_CMD_SB_PORT_POOL_GET: u8 = 19;	/* can dump */
pub const DEVLINK_CMD_SB_PORT_POOL_SET: u8 = 20;
pub const DEVLINK_CMD_SB_PORT_POOL_NEW: u8 = 21;
pub const DEVLINK_CMD_SB_PORT_POOL_DEL: u8 = 22;

pub const DEVLINK_CMD_SB_TC_POOL_BIND_GET: u8 = 23;	/* can dump */
pub const DEVLINK_CMD_SB_TC_POOL_BIND_SET: u8 = 24;
pub const DEVLINK_CMD_SB_TC_POOL_BIND_NEW: u8 = 25;
pub const DEVLINK_CMD_SB_TC_POOL_BIND_DEL: u8 = 26;

/* Shared buffer occupancy monitoring commands */
pub const DEVLINK_CMD_SB_OCC_SNAPSHOT: u8 = 27;
pub const DEVLINK_CMD_SB_OCC_MAX_CLEAR: u8 = 28;

pub const DEVLINK_CMD_ESWITCH_GET: u8 = 29;
pub const DEVLINK_CMD_ESWITCH_SET: u8 = 30;
pub const DEVLINK_CMD_DPIPE_TABLE_GET: u8 = 31;
pub const DEVLINK_CMD_DPIPE_ENTRIES_GET: u8 = 32;
pub const DEVLINK_CMD_DPIPE_HEADERS_GET: u8 = 33;
pub const DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET: u8 = 34;
pub const DEVLINK_CMD_RESOURCE_SET: u8 = 35;
pub const DEVLINK_CMD_RESOURCE_DUMP: u8 = 36;
pub const DEVLINK_CMD_RELOAD: u8 = 37;

pub const DEVLINK_CMD_PARAM_GET: u8 = 38;		/* can dump */
pub const DEVLINK_CMD_PARAM_SET: u8 = 39;
pub const DEVLINK_CMD_PARAM_NEW: u8 = 40;
pub const DEVLINK_CMD_PARAM_DEL: u8 = 41;

pub const DEVLINK_CMD_REGION_GET: u8 = 42;
pub const DEVLINK_CMD_REGION_SET: u8 = 43;
pub const DEVLINK_CMD_REGION_NEW: u8 = 44;
pub const DEVLINK_CMD_REGION_DEL: u8 = 45;
pub const DEVLINK_CMD_REGION_READ: u8 = 46;

pub const DEVLINK_CMD_PORT_PARAM_GET: u8 = 47;	/* can dump */
pub const DEVLINK_CMD_PORT_PARAM_SET: u8 = 48;
pub const DEVLINK_CMD_PORT_PARAM_NEW: u8 = 49;
pub const DEVLINK_CMD_PORT_PARAM_DEL: u8 = 50;

pub const DEVLINK_CMD_INFO_GET: u8 = 51;		/* can dump */

pub const DEVLINK_CMD_HEALTH_REPORTER_GET: u8 = 52;
pub const DEVLINK_CMD_HEALTH_REPORTER_SET: u8 = 53;
pub const DEVLINK_CMD_HEALTH_REPORTER_RECOVER: u8 = 54;
pub const DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE: u8 = 55;
pub const DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET: u8 = 56;
pub const DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR: u8 = 57;

pub const DEVLINK_CMD_FLASH_UPDATE: u8 = 58;
pub const DEVLINK_CMD_FLASH_UPDATE_END: u8 = 59;		/* notification only */
pub const DEVLINK_CMD_FLASH_UPDATE_STATUS: u8 = 60;	/* notification only */

pub const DEVLINK_CMD_TRAP_GET: u8 = 61;		/* can dump */
pub const DEVLINK_CMD_TRAP_SET: u8 = 62;
pub const DEVLINK_CMD_TRAP_NEW: u8 = 63;
pub const DEVLINK_CMD_TRAP_DEL: u8 = 64;

pub const DEVLINK_CMD_TRAP_GROUP_GET: u8 = 65;	/* can dump */
pub const DEVLINK_CMD_TRAP_GROUP_SET: u8 = 66;
pub const DEVLINK_CMD_TRAP_GROUP_NEW: u8 = 67;
pub const DEVLINK_CMD_TRAP_GROUP_DEL: u8 = 68;

pub const DEVLINK_CMD_TRAP_POLICER_GET: u8 = 69;	/* can dump */
pub const DEVLINK_CMD_TRAP_POLICER_SET: u8 = 70;
pub const DEVLINK_CMD_TRAP_POLICER_NEW: u8 = 71;
pub const DEVLINK_CMD_TRAP_POLICER_DEL: u8 = 72;

pub const DEVLINK_CMD_HEALTH_REPORTER_TEST: u8 = 73;

pub const DEVLINK_CMD_RATE_GET: u8 = 74;		/* can dump */
pub const DEVLINK_CMD_RATE_SET: u8 = 75;
pub const DEVLINK_CMD_RATE_NEW: u8 = 76;
pub const DEVLINK_CMD_RATE_DEL: u8 = 77;

/// Devlink attributes
pub const DEVLINK_ATTR_BUS_NAME: u16 = 1; /* string */
pub const DEVLINK_ATTR_LOCATION: u16 = 2; /* string */
pub const DEVLINK_ATTR_PORT_INDEX: u16 = 3; /* uint32 */
pub const DEVLINK_ATTR_PORT_TYPE: u16 = 4; /* uint16 */
pub const DEVLINK_ATTR_DESIRED_TYPE: u16 = 5; /* uint16 */
pub const DEVLINK_ATTR_NETDEV_IF_INDEX: u16 = 6; /* uint32 */
pub const DEVLINK_ATTR_NETDEV_NAME: u16 = 7; /* string */

pub const DEVLINK_ATTR_PORT_IBDEV_NAME: u16 = 8;		/* string */
pub const DEVLINK_ATTR_PORT_SPLIT_COUNT: u16 = 9;		/* u32 */
pub const DEVLINK_ATTR_PORT_SPLIT_GROUP: u16 = 10;		/* u32 */
pub const DEVLINK_ATTR_SB_INDEX: u16 = 11;			/* u32 */
pub const DEVLINK_ATTR_SB_SIZE: u16 = 12;			/* u32 */
pub const DEVLINK_ATTR_SB_INGRESS_POOL_COUNT: u16 = 13;	/* u16 */
pub const DEVLINK_ATTR_SB_EGRESS_POOL_COUNT: u16 = 14;	/* u16 */
pub const DEVLINK_ATTR_SB_INGRESS_TC_COUNT: u16 = 15;	/* u16 */
pub const DEVLINK_ATTR_SB_EGRESS_TC_COUNT: u16 = 16;	/* u16 */
pub const DEVLINK_ATTR_SB_POOL_INDEX: u16 = 17;		/* u16 */
pub const DEVLINK_ATTR_SB_POOL_TYPE: u16 = 18;		/* u8 */
pub const DEVLINK_ATTR_SB_POOL_SIZE: u16 = 19;		/* u32 */
pub const DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE: u16 = 20;	/* u8 */
pub const DEVLINK_ATTR_SB_THRESHOLD: u16 = 21;		/* u32 */
pub const DEVLINK_ATTR_SB_TC_INDEX: u16 = 22;		/* u16 */
pub const DEVLINK_ATTR_SB_OCC_CUR: u16 = 23;		/* u32 */
pub const DEVLINK_ATTR_SB_OCC_MAX: u16 = 24;		/* u32 */
pub const DEVLINK_ATTR_ESWITCH_MODE: u16 = 25;		/* u16 */
pub const DEVLINK_ATTR_ESWITCH_INLINE_MODE: u16 = 26;	/* u8 */
pub const DEVLINK_ATTR_DPIPE_TABLES: u16 = 27;		/* nested */
pub const DEVLINK_ATTR_DPIPE_TABLE: u16 = 28;		/* nested */
pub const DEVLINK_ATTR_DPIPE_TABLE_NAME: u16 = 29;		/* string */
pub const DEVLINK_ATTR_DPIPE_TABLE_SIZE: u16 = 30;		/* u64 */
pub const DEVLINK_ATTR_DPIPE_TABLE_MATCHES: u16 = 31;	/* nested */
pub const DEVLINK_ATTR_DPIPE_TABLE_ACTIONS: u16 = 32;	/* nested */
pub const DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED: u16 = 33;	/* u8 */
pub const DEVLINK_ATTR_DPIPE_ENTRIES: u16 = 34;		/* nested */
pub const DEVLINK_ATTR_DPIPE_ENTRY: u16 = 35;		/* nested */
pub const DEVLINK_ATTR_DPIPE_ENTRY_INDEX: u16 = 36;		/* u64 */
pub const DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES: u16 = 37;	/* nested */
pub const DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES: u16 = 38;	/* nested */
pub const DEVLINK_ATTR_DPIPE_ENTRY_COUNTER: u16 = 39;	/* u64 */
pub const DEVLINK_ATTR_DPIPE_MATCH: u16 = 40;		/* nested */
pub const DEVLINK_ATTR_DPIPE_MATCH_VALUE: u16 = 41;		/* nested */
pub const DEVLINK_ATTR_DPIPE_MATCH_TYPE: u16 = 42;		/* u32 */
pub const DEVLINK_ATTR_DPIPE_ACTION: u16 = 43;		/* nested */
pub const DEVLINK_ATTR_DPIPE_ACTION_VALUE: u16 = 44;		/* nested */
pub const DEVLINK_ATTR_DPIPE_ACTION_TYPE: u16 = 45;		/* u32 */
pub const DEVLINK_ATTR_DPIPE_VALUE: u16 = 46;
pub const DEVLINK_ATTR_DPIPE_VALUE_MASK: u16 = 47;
pub const DEVLINK_ATTR_DPIPE_VALUE_MAPPING: u16 = 48;	/* u32 */
pub const DEVLINK_ATTR_DPIPE_HEADERS: u16 = 49;		/* nested */
pub const DEVLINK_ATTR_DPIPE_HEADER: u16 = 50;		/* nested */
pub const DEVLINK_ATTR_DPIPE_HEADER_NAME: u16 = 51;		/* string */
pub const DEVLINK_ATTR_DPIPE_HEADER_ID: u16 = 52;		/* u32 */
pub const DEVLINK_ATTR_DPIPE_HEADER_FIELDS: u16 = 53;	/* nested */
pub const DEVLINK_ATTR_DPIPE_HEADER_GLOBAL: u16 = 54;	/* u8 */
pub const DEVLINK_ATTR_DPIPE_HEADER_INDEX: u16 = 55;	/* u32 */
pub const DEVLINK_ATTR_DPIPE_FIELD: u16 = 56;		/* nested */
pub const DEVLINK_ATTR_DPIPE_FIELD_NAME: u16 = 57;		/* string */
pub const DEVLINK_ATTR_DPIPE_FIELD_ID: u16 = 58;		/* u32 */
pub const DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH: u16 = 59;	/* u32 */
pub const DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE: u16 = 60;	/* u32 */
pub const DEVLINK_ATTR_ESWITCH_ENCAP_MODE: u16 = 62;	/* u8 */
pub const DEVLINK_ATTR_RESOURCE_LIST: u16 = 63;		/* nested */
pub const DEVLINK_ATTR_RESOURCE: u16 = 64;			/* nested */
pub const DEVLINK_ATTR_RESOURCE_NAME: u16 = 65;		/* string */
pub const DEVLINK_ATTR_RESOURCE_ID: u16 = 66;		/* u64 */
pub const DEVLINK_ATTR_RESOURCE_SIZE: u16 = 67;		/* u64 */
pub const DEVLINK_ATTR_RESOURCE_SIZE_NEW: u16 = 68;		/* u64 */
pub const DEVLINK_ATTR_RESOURCE_SIZE_VALID: u16 = 69;	/* u8 */
pub const DEVLINK_ATTR_RESOURCE_SIZE_MIN: u16 = 70;		/* u64 */
pub const DEVLINK_ATTR_RESOURCE_SIZE_MAX: u16 = 71;		/* u64 */
pub const DEVLINK_ATTR_RESOURCE_SIZE_GRAN: u16 = 72;        /* u64 */
pub const DEVLINK_ATTR_RESOURCE_UNIT: u16 = 73;		/* u8 */
pub const DEVLINK_ATTR_RESOURCE_OCC: u16 = 74;		/* u64 */
pub const DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID: u16 = 75;	/* u64 */
pub const DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS: u16 = 76;/* u64 */

pub const DEVLINK_ATTR_PORT_FLAVOUR: u16 = 77; /* uint16 */
pub const DEVLINK_ATTR_PORT_NUMBER: u16 = 78; /* uint32 */
pub const DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER: u16 = 79; /* u32 */

pub const DEVLINK_ATTR_PARAM: u16 = 80; /* nested */
pub const DEVLINK_ATTR_PARAM_NAME: u16 = 81; /* string */
pub const DEVLINK_ATTR_PARAM_GENERIC: u16 = 82; /* flag */
pub const DEVLINK_ATTR_PARAM_TYPE: u16 = 83; /* uint8  */
pub const DEVLINK_ATTR_PARAM_VALUES_LIST: u16 = 84; /* nested */
pub const DEVLINK_ATTR_PARAM_VALUE: u16 = 85; /* nested */
pub const DEVLINK_ATTR_PARAM_VALUE_DATA: u16 = 86; /* dynamic */
pub const DEVLINK_ATTR_PARAM_VALUE_CMODE: u16 = 87; /* uint8 */

pub const DEVLINK_ATTR_REGION_NAME: u16 = 88; /* string */
pub const DEVLINK_ATTR_REGION_SIZE: u16 = 89; /* uint64 */
pub const DEVLINK_ATTR_REGION_SNAPSHOTS: u16 = 90; /* nested */
pub const DEVLINK_ATTR_REGION_SNAPSHOT: u16 = 91; /* nested */
pub const DEVLINK_ATTR_REGION_SNAPSHOT_ID: u16 = 92; /* uint32 */
pub const DEVLINK_ATTR_REGION_CHUNKS: u16 = 93; /* nested */
pub const DEVLINK_ATTR_REGION_CHUNK: u16 = 94; /* nested */
pub const DEVLINK_ATTR_REGION_CHUNK_DATA: u16 = 95; /* binary */
pub const DEVLINK_ATTR_REGION_CHUNK_ADDR: u16 = 96; /* uint64 */
pub const DEVLINK_ATTR_REGION_CHUNK_LEN: u16 = 97; /* uint64 */

pub const DEVLINK_ATTR_INFO_DRIVER_NAME: u16 = 98; /* string */
pub const DEVLINK_ATTR_INFO_SERIAL_NUMBER: u16 = 99; /* string */
pub const DEVLINK_ATTR_INFO_VERSION_FIXED: u16 = 100; /* nested */
pub const DEVLINK_ATTR_INFO_VERSION_RUNNING: u16 = 101; /* nested */
pub const DEVLINK_ATTR_INFO_VERSION_STORED: u16 = 102; /* nested */
pub const DEVLINK_ATTR_INFO_VERSION_NAME: u16 = 103; /* string */
pub const DEVLINK_ATTR_INFO_VERSION_VALUE: u16 = 104; /* string */

pub const DEVLINK_ATTR_SB_POOL_CELL_SIZE: u16 = 105;		/* u32 */

pub const DEVLINK_ATTR_FMSG: u16 = 106;			/* nested */
pub const DEVLINK_ATTR_FMSG_OBJ_NEST_START: u16 = 107;	/* flag */
pub const DEVLINK_ATTR_FMSG_PAIR_NEST_START: u16 = 108;	/* flag */
pub const DEVLINK_ATTR_FMSG_ARR_NEST_START: u16 = 109;	/* flag */
pub const DEVLINK_ATTR_FMSG_NEST_END: u16 = 110;		/* flag */
pub const DEVLINK_ATTR_FMSG_OBJ_NAME: u16 = 111;		/* string */
pub const DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE: u16 = 112;	/* u8 */
pub const DEVLINK_ATTR_FMSG_OBJ_VALUE_DATA: u16 = 113;	/* dynamic */

pub const DEVLINK_ATTR_HEALTH_REPORTER: u16 = 114;			/* nested */
pub const DEVLINK_ATTR_HEALTH_REPORTER_NAME: u16 = 115;		/* string */
pub const DEVLINK_ATTR_HEALTH_REPORTER_STATE: u16 = 116;		/* u8 */
pub const DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT: u16 = 117;		/* u64 */
pub const DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT: u16 = 118;	/* u64 */
pub const DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS: u16 = 119;		/* u64 */
pub const DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD: u16 = 120;	/* u64 */
pub const DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER: u16 = 121;	/* u8 */

pub const DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME: u16 = 122; /* string */
pub const DEVLINK_ATTR_FLASH_UPDATE_COMPONENT: u16 = 123;	/* string */
pub const DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG: u16 = 124;	/* string */
pub const DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE: u16 = 125;	/* u64 */
pub const DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL: u16 = 126;	/* u64 */

pub const DEVLINK_ATTR_PORT_PCI_PF_NUMBER: u16 = 127;	/* u16 */
pub const DEVLINK_ATTR_PORT_PCI_VF_NUMBER: u16 = 128;	/* u16 */

pub const DEVLINK_ATTR_STATS: u16 = 129;	/* nested */

pub const DEVLINK_ATTR_TRAP_NAME: u16 = 130;	/* string */
/* enum devlink_trap_action */
pub const DEVLINK_ATTR_TRAP_ACTION: u16 = 131;	/* u8 */
/* enum devlink_trap_type */
pub const DEVLINK_ATTR_TRAP_TYPE: u16 = 132;	/* u8 */
pub const DEVLINK_ATTR_TRAP_GENERIC: u16 = 133;	/* flag */
pub const DEVLINK_ATTR_TRAP_METADATA: u16 = 134;	/* nested */
pub const DEVLINK_ATTR_TRAP_GROUP_NAME: u16 = 135;	/* string */
pub const DEVLINK_ATTR_RELOAD_FAILED: u16 = 136; /* uint8 */

pub const DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS: u16 = 137;	/* u64 */

pub const DEVLINK_ATTR_NETNS_FD: u16 = 138;			/* u32 */
pub const DEVLINK_ATTR_NETNS_PID: u16 = 139;			/* u32 */
pub const DEVLINK_ATTR_NETNS_ID: u16 = 140;			/* u32 */

pub const DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP: u16 = 141;	/* u8 */

pub const DEVLINK_ATTR_TRAP_POLICER_ID: u16 = 142;			/* u32 */
pub const DEVLINK_ATTR_TRAP_POLICER_RATE: u16 = 143;			/* u64 */
pub const DEVLINK_ATTR_TRAP_POLICER_BURST: u16 = 144;		/* u64 */

pub const DEVLINK_ATTR_PORT_FUNCTION: u16 = 145;			/* nested */

pub const DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER: u16 = 146;	/* string */

pub const DEVLINK_ATTR_PORT_LANES: u16 = 147;			/* u32 */
pub const DEVLINK_ATTR_PORT_SPLITTABLE: u16 = 148;			/* u8 */

pub const DEVLINK_ATTR_PORT_EXTERNAL: u16 = 149;		/* u8 */
pub const DEVLINK_ATTR_PORT_CONTROLLER_NUMBER: u16 = 150;	/* u32 */

pub const DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT: u16 = 151;	/* u64 */
pub const DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK: u16 = 152;	/* bitfield32 */

pub const DEVLINK_ATTR_RELOAD_ACTION: u16 = 153; /* uint8 */
pub const DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED: u16 = 154; /* bitfield32 */
pub const DEVLINK_ATTR_RELOAD_LIMITS: u16 = 155; /* bitfield32 */

pub const DEVLINK_ATTR_DEV_STATS: u16 = 156; /* nested */
pub const DEVLINK_ATTR_RELOAD_STATS: u16 = 157; /* nested */
pub const DEVLINK_ATTR_RELOAD_STATS_ENTRY: u16 = 158; /* nested */
pub const DEVLINK_ATTR_RELOAD_STATS_LIMIT: u16 = 159; /* uint8 */
pub const DEVLINK_ATTR_RELOAD_STATS_VALUE: u16 = 160; /* uint32 */
pub const DEVLINK_ATTR_REMOTE_RELOAD_SATS: u16 = 161; /* nested */
pub const DEVLINK_ATTR_RELOAD_ACTION_INFO: u16 = 162; /* nested */
pub const DEVLINK_ATTR_RELAOD_ACTION_STATS: u16 = 163; /* nested */

pub const DEVLINK_ATTR_PORT_PCI_SF_NUMBER: u16 = 164;	/* u32 */

pub const DEVLINK_ATTR_RATE_TYPE: u16 = 165;			/* u16 */
pub const DEVLINK_ATTR_RATE_TX_SHARE: u16 = 166;		/* u64 */
pub const DEVLINK_ATTR_RATE_TX_MAX: u16 = 167;		/* u64 */
pub const DEVLINK_ATTR_RATE_NODE_NAME: u16 = 168;		/* string */
pub const DEVLINK_ATTR_RATE_PARENT_NODE_NAME: u16 = 169;	/* string */

pub const DEVLINK_ATTR_REGION_MAX_SNAPSHOTS: u16 =170; /* uint32 */