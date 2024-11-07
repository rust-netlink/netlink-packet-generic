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
/// DEVLINK_CMD_GET: Get all devices supporting devlink
pub const DEVLINK_CMD_GET: u8 = 1;
pub const DEVLINK_CMD_DEVICE_DATA: u8 = 3;
pub const DEVLINK_CMD_PORT_GET: u8 = 5;
pub const DEVLINK_CMD_RELOAD: u8 = 37;
pub const DEVLINK_CMD_PARAM_GET: u8 = 38;
pub const DEVLINK_CMD_PARAM_SET: u8 = 39;
pub const DEVLINK_CMD_REGION_GET: u8 = 42;
pub const DEVLINK_CMD_REGION_SET: u8 = 43;
pub const DEVLINK_CMD_REGION_NEW: u8 = 44;
pub const DEVLINK_CMD_REGION_DEL: u8 = 45;
pub const DEVLINK_CMD_REGION_READ: u8 = 46;

/// DEVLINK_CMD_INFO_GET: Get specific device info
pub const DEVLINK_CMD_INFO_GET: u8 = 51;

/// Flas update devlink commands
pub const DEVLINK_CMD_FLASH_UPDATE: u8 = 58;
pub const DEVLINK_CMD_FLASH_UPDATE_END: u8 = 59;
pub const DEVLINK_CMD_FLASH_UPDATE_STATUS: u8 = 60;

pub const DEVLINK_ATTR_BUS_NAME: u16 = 1; /* string */
pub const DEVLINK_ATTR_LOCATION: u16 = 2; /* string */
pub const DEVLINK_ATTR_PORT_INDEX: u16 = 3; /* uint32 */
pub const DEVLINK_ATTR_PORT_TYPE: u16 = 4; /* uint16 */
pub const DEVLINK_ATTR_DESIRED_TYPE: u16 = 5; /* uint16 */
pub const DEVLINK_ATTR_NETDEV_IF_INDEX: u16 = 6; /* uint32 */
pub const DEVLINK_ATTR_NETDEV_NAME: u16 = 7; /* string */

pub const DEVLINK_ATTR_PORT_FLAVOUR: u16 = 77; /* uint16 */
pub const DEVLINK_ATTR_PORT_NUMBER: u16 = 78; /* uint32 */

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

pub const DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME: u16 = 122; /* string */

pub const DEVLINK_ATTR_RELOAD_FAILED: u16 = 136; /* uint8 */
pub const DEVLINK_ATTR_RELOAD_ACTION: u16 = 153; /* uint8 */
pub const DEVLINK_ATTR_DEVICE_STATS: u16 = 156; /* nested */
