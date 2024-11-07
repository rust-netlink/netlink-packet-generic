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
    GetPort,
    Reload,
    GetParams,
    SetParams,
    GetRegion,
    SetRegion,
    CreatRegion,
    DestroyRegion,
    ReadRegion,
    GetDeviceInfo,
    UpdateFlash,
    FlashUdpateEnd,
    FlashUdpateStatus,
    DeviceData,
}

impl From<GenlDevlinkCmd> for u8 {
    fn from(cmd: GenlDevlinkCmd) -> u8 {
        use GenlDevlinkCmd::*;
        match cmd {
            GetDevices => DEVLINK_CMD_GET,
            GetPort => DEVLINK_CMD_PORT_GET,
            Reload => DEVLINK_CMD_RELOAD,
            GetParams => DEVLINK_CMD_PARAM_GET,
            SetParams => DEVLINK_CMD_PARAM_SET,
            GetRegion => DEVLINK_CMD_REGION_GET,
            SetRegion => DEVLINK_CMD_REGION_SET,
            CreatRegion => DEVLINK_CMD_REGION_NEW,
            DestroyRegion => DEVLINK_CMD_REGION_DEL,
            ReadRegion => DEVLINK_CMD_REGION_READ,
            GetDeviceInfo => DEVLINK_CMD_INFO_GET,
            UpdateFlash => DEVLINK_CMD_FLASH_UPDATE,
            FlashUdpateEnd => DEVLINK_CMD_FLASH_UPDATE_END,
            FlashUdpateStatus => DEVLINK_CMD_FLASH_UPDATE_STATUS,
            DeviceData => DEVLINK_CMD_DEVICE_DATA, // consider to return error, this cannot be sent to kernel driver (probably)
        }
    }
}

impl TryFrom<u8> for GenlDevlinkCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use GenlDevlinkCmd::*;
        Ok(match value {
            DEVLINK_CMD_GET => GetDevices,
            DEVLINK_CMD_PORT_GET => GetPort,
            DEVLINK_CMD_RELOAD => Reload,
            DEVLINK_CMD_PARAM_GET => GetParams,
            DEVLINK_CMD_PARAM_SET => SetParams,
            DEVLINK_CMD_REGION_GET => GetRegion,
            DEVLINK_CMD_REGION_SET => SetRegion,
            DEVLINK_CMD_REGION_NEW => CreatRegion,
            DEVLINK_CMD_REGION_DEL => DestroyRegion,
            DEVLINK_CMD_REGION_READ => ReadRegion,
            DEVLINK_CMD_INFO_GET => GetDeviceInfo,
            DEVLINK_CMD_FLASH_UPDATE => UpdateFlash,
            DEVLINK_CMD_FLASH_UPDATE_END => FlashUdpateEnd,
            DEVLINK_CMD_FLASH_UPDATE_STATUS => FlashUdpateStatus,
            DEVLINK_CMD_DEVICE_DATA => DeviceData,
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
