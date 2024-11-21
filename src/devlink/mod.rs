// SPDX-License-Identifier: MIT

//! Generic netlink devlink implementation
//!
//! This module provides the definition of the devlink packet.
//! It also serves as an example for creating a generic family.

use self::nldev::*;
use crate::{constants::*, traits::*, GenlHeader};
use anyhow::Context;
use netlink_packet_utils::{nla::NlasIterator, traits::*, DecodeError};
use std::convert::{TryFrom, TryInto};

/// Netlink attributes for this family
pub mod nldev;

/// Command code definition of Netlink Devlink family
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenlDevlinkCmd {
    GetDevices,
    SetDevice,
    NewDevice,
    DeleteDevice,
    GetPort,
    SetPort,
    NewPort,
    DeletePort,
    SplitPort,
    UnsplitPort,
    GetSb,
    SetSb,
    NewSb,
    DeleteSb,
    GetSbPool,
    SetSbPool,
    NewSbPool,
    DeleteSbPool,
    GetSbPortPool,
    SetSbPortPool,
    NewSbPortPool,
    DeleteSbPortPool,
    GetSbTcPoolBind,
    SetSbTcPoolBind,
    NewSbTcPoolBind,
    DeleteSbTcPoolBind,
    SbOccSnapshot,
    SbOccMaxClear,
    GetEswitch,
    SetEswitch,
    GetDpipeTable,
    GetDpipeEntries,
    GetDpipeHeaders,
    SetDpipeTableCounters,
    SetResource,
    DumpResource,
    Reload,
    GetParams,
    SetParams,
    NewParam,
    DeleteParam,
    GetRegion,
    SetRegion,
    CreatRegion,
    DeleteRegion,
    ReadRegion,
    GetPortParam,
    SetPortParam,
    NewPortParam,
    DeletePortParam,
    GetDeviceInfo,
    GetHealthReport,
    SetHealthReport,
    RecoverHealthReport,
    DaignoseHealthReport,
    GetHealthReportDump,
    ClearHealthReportDump,
    UpdateFlash,
    FlashUdpateEnd,
    FlashUdpateStatus,
    GetTrap,
    SetTrap,
    NewTrap,
    DeleteTrap,
    GetTrapGroup,
    SetTrapGroup,
    NewTrapGroup,
    DeleteTrapGroup,
    GetTrapPolicer,
    SetTrapPolicer,
    NewTrapPolicer,
    DeleteTrapPolicer,
    TestHealthReport,
    GetRate,
    SetRate,
    NewRate,
    DeleteRate,
}

impl GenlDevlinkCmd {
    pub fn dump_capable(&self) -> bool {
        use GenlDevlinkCmd::*;
        match self {
            GetDevices => true,
            GetPort => true,
            GetSb => true,
            GetSbPool => true,
            GetSbPortPool => true,
            GetSbTcPoolBind => true,
            GetParams => true,
            GetRegion => true,
            GetPortParam => true,
            GetDeviceInfo => true,
            GetTrap => true,
            GetTrapGroup => true,
            GetTrapPolicer => true,
            GetRate => true,
            _ => false,
        }
    }
}

impl From<GenlDevlinkCmd> for u8 {
    fn from(cmd: GenlDevlinkCmd) -> u8 {
        use GenlDevlinkCmd::*;
        match cmd {
            GetDevices => DEVLINK_CMD_GET,
            SetDevice => DEVLINK_CMD_SET,
            NewDevice => DEVLINK_CMD_NEW,
            DeleteDevice => DEVLINK_CMD_DEL,            
            GetPort => DEVLINK_CMD_PORT_GET,
            SetPort => DEVLINK_CMD_PORT_SET,
            NewPort => DEVLINK_CMD_PORT_NEW,
            DeletePort => DEVLINK_CMD_PORT_DEL,
            SplitPort => DEVLINK_CMD_PORT_SPLIT,
            UnsplitPort => DEVLINK_CMD_PORT_UNSPLIT,
            GetSb => DEVLINK_CMD_SB_GET,
            SetSb => DEVLINK_CMD_SB_SET,
            NewSb => DEVLINK_CMD_SB_NEW,
            DeleteSb => DEVLINK_CMD_SB_DEL,
            GetSbPool => DEVLINK_CMD_SB_POOL_GET,
            SetSbPool => DEVLINK_CMD_SB_POOL_SET,
            NewSbPool => DEVLINK_CMD_SB_POOL_NEW,
            DeleteSbPool => DEVLINK_CMD_SB_POOL_DEL,
            GetSbPortPool => DEVLINK_CMD_SB_PORT_POOL_GET,
            SetSbPortPool => DEVLINK_CMD_SB_PORT_POOL_SET,
            NewSbPortPool => DEVLINK_CMD_SB_PORT_POOL_NEW,
            DeleteSbPortPool => DEVLINK_CMD_SB_PORT_POOL_DEL,
            GetSbTcPoolBind => DEVLINK_CMD_SB_TC_POOL_BIND_GET,
            SetSbTcPoolBind => DEVLINK_CMD_SB_TC_POOL_BIND_SET,
            NewSbTcPoolBind => DEVLINK_CMD_SB_TC_POOL_BIND_NEW,
            DeleteSbTcPoolBind => DEVLINK_CMD_SB_TC_POOL_BIND_DEL,
            SbOccSnapshot => DEVLINK_CMD_SB_OCC_SNAPSHOT,
            SbOccMaxClear => DEVLINK_CMD_SB_OCC_MAX_CLEAR,
            GetEswitch => DEVLINK_CMD_ESWITCH_GET,
            SetEswitch => DEVLINK_CMD_ESWITCH_SET,
            GetDpipeTable => DEVLINK_CMD_DPIPE_TABLE_GET,
            GetDpipeEntries => DEVLINK_CMD_DPIPE_ENTRIES_GET,
            GetDpipeHeaders => DEVLINK_CMD_DPIPE_HEADERS_GET,
            SetDpipeTableCounters => DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET,
            SetResource => DEVLINK_CMD_RESOURCE_SET,
            DumpResource => DEVLINK_CMD_RESOURCE_DUMP,
            Reload => DEVLINK_CMD_RELOAD,
            GetParams => DEVLINK_CMD_PARAM_GET,
            SetParams => DEVLINK_CMD_PARAM_SET,
            NewParam => DEVLINK_CMD_PARAM_NEW,
            DeleteParam => DEVLINK_CMD_PARAM_DEL,
            GetRegion => DEVLINK_CMD_REGION_GET,
            SetRegion => DEVLINK_CMD_REGION_SET,
            CreatRegion => DEVLINK_CMD_REGION_NEW,
            DeleteRegion => DEVLINK_CMD_REGION_DEL,
            ReadRegion => DEVLINK_CMD_REGION_READ,
            GetPortParam => DEVLINK_CMD_PORT_PARAM_GET,
            SetPortParam => DEVLINK_CMD_PORT_PARAM_SET,
            NewPortParam => DEVLINK_CMD_PORT_PARAM_NEW,
            DeletePortParam => DEVLINK_CMD_PORT_PARAM_DEL,
            GetDeviceInfo => DEVLINK_CMD_INFO_GET,
            GetHealthReport => DEVLINK_CMD_HEALTH_REPORTER_GET,
            SetHealthReport => DEVLINK_CMD_HEALTH_REPORTER_SET,
            RecoverHealthReport => DEVLINK_CMD_HEALTH_REPORTER_RECOVER,
            DaignoseHealthReport => DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE,
            GetHealthReportDump => DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET,
            ClearHealthReportDump => DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR,
            UpdateFlash => DEVLINK_CMD_FLASH_UPDATE,
            FlashUdpateEnd => DEVLINK_CMD_FLASH_UPDATE_END,
            FlashUdpateStatus => DEVLINK_CMD_FLASH_UPDATE_STATUS,
            GetTrap => DEVLINK_CMD_TRAP_GET,
            SetTrap => DEVLINK_CMD_TRAP_SET, 
            NewTrap => DEVLINK_CMD_TRAP_NEW,
            DeleteTrap => DEVLINK_CMD_TRAP_DEL,
            GetTrapGroup => DEVLINK_CMD_TRAP_GROUP_GET,
            SetTrapGroup => DEVLINK_CMD_TRAP_GROUP_SET, 
            NewTrapGroup => DEVLINK_CMD_TRAP_GROUP_NEW,
            DeleteTrapGroup => DEVLINK_CMD_TRAP_GROUP_DEL,
            GetTrapPolicer => DEVLINK_CMD_TRAP_POLICER_GET,
            SetTrapPolicer => DEVLINK_CMD_TRAP_POLICER_SET,
            NewTrapPolicer => DEVLINK_CMD_TRAP_POLICER_NEW,
            DeleteTrapPolicer => DEVLINK_CMD_TRAP_POLICER_DEL,
            TestHealthReport => DEVLINK_CMD_HEALTH_REPORTER_TEST,
            GetRate => DEVLINK_CMD_RATE_GET,
            SetRate => DEVLINK_CMD_RATE_SET,
            NewRate => DEVLINK_CMD_RATE_NEW,
            DeleteRate => DEVLINK_CMD_RATE_DEL,
        }
    }
}

impl TryFrom<u8> for GenlDevlinkCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use GenlDevlinkCmd::*;
        Ok(match value {
            DEVLINK_CMD_GET => GetDevices,
            DEVLINK_CMD_SET => SetDevice,
            DEVLINK_CMD_NEW => NewDevice,
            DEVLINK_CMD_DEL => DeleteDevice,
            DEVLINK_CMD_PORT_GET => GetPort,
            DEVLINK_CMD_PORT_SET => SetPort,
            DEVLINK_CMD_PORT_NEW => NewPort,
            DEVLINK_CMD_PORT_DEL => DeletePort,
            DEVLINK_CMD_PORT_SPLIT => SplitPort,
            DEVLINK_CMD_PORT_UNSPLIT => UnsplitPort,
            DEVLINK_CMD_SB_GET => GetSb,		/* can dump */
            DEVLINK_CMD_SB_SET => SetSb,
            DEVLINK_CMD_SB_NEW => NewSb,
            DEVLINK_CMD_SB_DEL => DeleteSb,
            DEVLINK_CMD_SB_POOL_GET => GetSbPool,	/* can dump */
            DEVLINK_CMD_SB_POOL_SET => SetSbPool,
            DEVLINK_CMD_SB_POOL_NEW => NewSbPool,
            DEVLINK_CMD_SB_POOL_DEL => DeleteSbPool,
            DEVLINK_CMD_SB_PORT_POOL_GET => GetSbPortPool,	/* can dump */
            DEVLINK_CMD_SB_PORT_POOL_SET => SetSbPortPool,
            DEVLINK_CMD_SB_PORT_POOL_NEW => NewSbPortPool,
            DEVLINK_CMD_SB_PORT_POOL_DEL => DeleteSbPortPool,
            DEVLINK_CMD_SB_TC_POOL_BIND_GET => GetSbTcPoolBind,	/* can dump */
            DEVLINK_CMD_SB_TC_POOL_BIND_SET => SetSbTcPoolBind,
            DEVLINK_CMD_SB_TC_POOL_BIND_NEW => NewSbTcPoolBind,
            DEVLINK_CMD_SB_TC_POOL_BIND_DEL => DeleteSbTcPoolBind,
            DEVLINK_CMD_SB_OCC_SNAPSHOT => SbOccSnapshot,
            DEVLINK_CMD_SB_OCC_MAX_CLEAR => SbOccMaxClear,
            DEVLINK_CMD_ESWITCH_GET => GetEswitch,
            DEVLINK_CMD_ESWITCH_SET => SetEswitch,
            DEVLINK_CMD_DPIPE_TABLE_GET => GetDpipeTable,
            DEVLINK_CMD_DPIPE_ENTRIES_GET => GetDpipeEntries,
            DEVLINK_CMD_DPIPE_HEADERS_GET => GetDpipeHeaders,
            DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET => SetDpipeTableCounters,
            DEVLINK_CMD_RESOURCE_SET => SetResource,
            DEVLINK_CMD_RESOURCE_DUMP => DumpResource,
            DEVLINK_CMD_RELOAD => Reload,
            DEVLINK_CMD_PARAM_GET => GetParams,
            DEVLINK_CMD_PARAM_SET => SetParams,
            DEVLINK_CMD_PARAM_NEW => NewParam,
            DEVLINK_CMD_PARAM_DEL => DeleteParam,
            DEVLINK_CMD_REGION_GET => GetRegion,
            DEVLINK_CMD_REGION_SET => SetRegion,
            DEVLINK_CMD_REGION_NEW => CreatRegion,
            DEVLINK_CMD_REGION_DEL => DeleteRegion,
            DEVLINK_CMD_REGION_READ => ReadRegion,
            DEVLINK_CMD_PORT_PARAM_GET => GetPortParam,	/* can dump */
            DEVLINK_CMD_PORT_PARAM_SET => SetPortParam,
            DEVLINK_CMD_PORT_PARAM_NEW => NewPortParam,
            DEVLINK_CMD_PORT_PARAM_DEL => DeletePortParam,
            DEVLINK_CMD_INFO_GET => GetDeviceInfo,
            DEVLINK_CMD_HEALTH_REPORTER_GET => GetHealthReport,
            DEVLINK_CMD_HEALTH_REPORTER_SET => SetHealthReport,
            DEVLINK_CMD_HEALTH_REPORTER_RECOVER => RecoverHealthReport,
            DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE => DaignoseHealthReport,
            DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET => GetHealthReportDump,
            DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR => ClearHealthReportDump,
            DEVLINK_CMD_FLASH_UPDATE => UpdateFlash,
            DEVLINK_CMD_FLASH_UPDATE_END => FlashUdpateEnd,
            DEVLINK_CMD_FLASH_UPDATE_STATUS => FlashUdpateStatus,
            DEVLINK_CMD_TRAP_GET => GetTrap,		/* can dump */
            DEVLINK_CMD_TRAP_SET => SetTrap,
            DEVLINK_CMD_TRAP_NEW => NewTrap,
            DEVLINK_CMD_TRAP_DEL => DeleteTrap,
            DEVLINK_CMD_TRAP_GROUP_GET => GetTrapGroup,	/* can dump */
            DEVLINK_CMD_TRAP_GROUP_SET => SetTrapGroup,
            DEVLINK_CMD_TRAP_GROUP_NEW => NewTrapGroup,
            DEVLINK_CMD_TRAP_GROUP_DEL => DeleteTrapGroup,
            DEVLINK_CMD_TRAP_POLICER_GET => GetTrapPolicer,	/* can dump */
            DEVLINK_CMD_TRAP_POLICER_SET => SetTrapPolicer,
            DEVLINK_CMD_TRAP_POLICER_NEW => NewTrapPolicer,
            DEVLINK_CMD_TRAP_POLICER_DEL => DeleteTrapPolicer,
            DEVLINK_CMD_HEALTH_REPORTER_TEST => TestHealthReport,
            DEVLINK_CMD_RATE_GET => GetRate,		/* can dump */
            DEVLINK_CMD_RATE_SET => SetRate,
            DEVLINK_CMD_RATE_NEW => NewRate,
            DEVLINK_CMD_RATE_DEL => DeleteRate,
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unknown devlink command: {cmd}"
                )))
            }
        })
    }
}

/// Payload of generic netlink controller
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenlDevlink {
    /// Command code of this message
    pub cmd: GenlDevlinkCmd,
    /// Netlink attributes in this message
    pub nldev: Vec<GenlDevlinkAttrs>,
}

impl GenlFamily for GenlDevlink {
    fn family_name() -> &'static str {
        "devlink"
    }

    fn family_id(&self) -> u16 {
        GENL_ID_DEVLINK
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }

    fn version(&self) -> u8 {
        1
    }
}

impl Emitable for GenlDevlink {
    fn emit(&self, buffer: &mut [u8]) {
        self.nldev.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.nldev.as_slice().buffer_len()
    }
}

impl ParseableParametrized<[u8], GenlHeader> for GenlDevlink {
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.try_into()?,
            nldev: parse_ctrlnldev(buf)?,
        })
    }
}

fn parse_ctrlnldev(buf: &[u8]) -> Result<Vec<GenlDevlinkAttrs>, DecodeError> {
    let nldev = NlasIterator::new(buf)
        .map(|nlattr| {
            nlattr.and_then(|nlattr| GenlDevlinkAttrs::parse(&nlattr))
        })
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse control message attributes")?;

    Ok(nldev)
}
