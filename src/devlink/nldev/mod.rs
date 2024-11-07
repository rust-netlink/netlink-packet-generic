// SPDX-License-Identifier: MIT

use crate::constants::*;
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::mem::size_of_val;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenlDevlinkAttrs {
    BusName(String),
    Location(String),
    PortIndex(u32),
    PortType(u16),
    DesiredType(u16),
    NetdevIndex(u32),
    NetdevName(String),
    PortFlavour(u16),
    PortNumber(u32),
    // Param(Vec<ParamAttr>),
    ParamName(String),
    ParamGeneric(bool),
    ParamType(u8),
    // ParamValueList(Vec<ParamAttr>),
    ParamValue(u64),
    // ParamValueData(Vec<Vec<ParamAttr>>),
    ParamValueCmode(u8),
    RegionName(String),
    RegionSize(u64),
    // RegionSnapshots(Vec<Vec<ParamAttr>>),
    // RegionSnapshot(Vec<ParamAttr>),
    RegionSnapshotId(u32),
    // RegionChunks(Vec<Vec<ParamAttr>),
    // RegionChunk(Vec<ParamAttr>),
    RegionChunkData(Vec<u8>),
    RegionChunkOffset(u64),
    RegionChunkSize(u64),
    InfoDriverName(String),
    InfoSerialNo(String),
    InfoVersionFixed(Vec<GenlDevlinkAttrs>),
    InfoVersionRunning(Vec<GenlDevlinkAttrs>),
    InfoVersionStored(Vec<GenlDevlinkAttrs>),
    InfoVersionName(String),
    InfoVersionValue(String),
    FlashUpdateFileName(String),
    ReloadStatus(u8),
    ReloadAction(u8),
    Unknown(String), 
}

impl Nla for GenlDevlinkAttrs {
    fn value_len(&self) -> usize {
        use GenlDevlinkAttrs::*;
        match self {
            BusName(s) => s.len() + 1,
            Location(s) => s.len() + 1,
            PortIndex(v) => size_of_val(v),
            PortType(v) => size_of_val(v),
            DesiredType(v) => size_of_val(v),
            NetdevIndex(v) => size_of_val(v),
            NetdevName(s) => s.len() + 1,
            PortFlavour(v) => size_of_val(v),
            PortNumber(v) => size_of_val(v),
            // Param(Vec<ParamAttr>),
            ParamName(s) => s.len() + 1,
            ParamGeneric(v) => size_of_val(v),
            ParamType(v) => size_of_val(v),
            // ParamValueList(Vec<ParamAttr>),
            ParamValue(v) => size_of_val(v),
            // ParamValueData(Vec<Vec<ParamAttr>>),
            ParamValueCmode(v) => size_of_val(v),
            RegionName(s) => s.len() + 1,
            RegionSize(v) => size_of_val(v),
            // RegionSnapshots(Vec<Vec<ParamAttr>>),
            // RegionSnapshot(Vec<ParamAttr>),
            RegionSnapshotId(v) => size_of_val(v),
            // RegionChunks(Vec<Vec<ParamAttr>),
            // RegionChunk(Vec<ParamAttr>),
            RegionChunkData(nla) => nla.len(),
            RegionChunkOffset(v) => size_of_val(v),
            RegionChunkSize(v) => size_of_val(v),
            InfoDriverName(s) => s.len() + 1,
            InfoSerialNo(s) => s.len() + 1,
            InfoVersionFixed(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            InfoVersionRunning(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            InfoVersionStored(v) => v.iter().map(|nla| nla.buffer_len()).sum(),
            InfoVersionName(s) => s.len() + 1,
            InfoVersionValue(s) => s.len() + 1,
            FlashUpdateFileName(s) => s.len() + 1,
            ReloadStatus(v) => size_of_val(v),
            ReloadAction(v) => size_of_val(v),
            Unknown(s) => s.len() + 1,
        }
    }

    fn kind(&self) -> u16 {
        use GenlDevlinkAttrs::*;
        match self {
            BusName(_) => DEVLINK_ATTR_BUS_NAME,
            Location(_) => DEVLINK_ATTR_LOCATION,
            PortIndex(_) => DEVLINK_ATTR_PORT_INDEX,
            PortType(_) => DEVLINK_ATTR_PORT_TYPE,
            DesiredType(_) => DEVLINK_ATTR_DESIRED_TYPE,
            NetdevIndex(_) => DEVLINK_ATTR_NETDEV_IF_INDEX,
            NetdevName(_) => DEVLINK_ATTR_NETDEV_NAME,
            PortFlavour(_) => DEVLINK_ATTR_PORT_FLAVOUR,
            PortNumber(_) => DEVLINK_ATTR_PORT_NUMBER,
            // Param(_) => DEVLINK_ATTR_PARAM,
            ParamName(_) => DEVLINK_ATTR_PARAM_NAME,
            ParamGeneric(_) => DEVLINK_ATTR_PARAM_GENERIC,
            ParamType(_) => DEVLINK_ATTR_PARAM_TYPE,
            // ParamValueList(_) => DEVLINK_ATTR_PARAM_VALUE_LIST,
            ParamValue(_) => DEVLINK_ATTR_PARAM_VALUE,
            // ParamValueData(_) => DEVLINK_ATTR_PARAM_VALUE_DATA,
            ParamValueCmode(_) => DEVLINK_ATTR_PARAM_VALUE_CMODE,
            RegionName(_) => DEVLINK_ATTR_REGION_NAME,
            RegionSize(_) => DEVLINK_ATTR_REGION_SIZE,
            // RegionSnapshots(_) => DEVLINK_ATTR_REGION_SNAPSHOTS,
            // RegionSnapshot(_) => DEVLINK_ATTR_REGION_SNAPSHOT,
            RegionSnapshotId(_) => DEVLINK_ATTR_REGION_SNAPSHOT_ID,
            // RegionChunks(_) => DEVLINK_ATTR_REGION_CHUNKS,
            // RegionChunk(_) => DEVLINK_ATTR_REGION_CHUNK,
            RegionChunkData(_) => DEVLINK_ATTR_REGION_CHUNK_DATA,
            RegionChunkOffset(_) => DEVLINK_ATTR_REGION_CHUNK_ADDR,
            RegionChunkSize(_) => DEVLINK_ATTR_REGION_SIZE,
            InfoDriverName(_) => DEVLINK_ATTR_INFO_DRIVER_NAME,
            InfoSerialNo(_) => DEVLINK_ATTR_INFO_SERIAL_NUMBER,
            InfoVersionFixed(_) => DEVLINK_ATTR_INFO_VERSION_FIXED,
            InfoVersionRunning(_) => DEVLINK_ATTR_INFO_VERSION_RUNNING,
            InfoVersionStored(_) => DEVLINK_ATTR_INFO_VERSION_STORED,
            InfoVersionName(_) => DEVLINK_ATTR_INFO_VERSION_NAME,
            InfoVersionValue(_) => DEVLINK_ATTR_INFO_VERSION_VALUE,
            FlashUpdateFileName(_) => DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME,
            ReloadStatus(_) => DEVLINK_ATTR_RELOAD_FAILED,
            ReloadAction(_) => DEVLINK_ATTR_RELOAD_ACTION,
            Unknown(_) => 0,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use GenlDevlinkAttrs::*;
        match self {
            BusName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Location(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            PortIndex(v) => NativeEndian::write_u32(buffer, *v),
            PortType(v) => NativeEndian::write_u16(buffer, *v),
            DesiredType(v) => NativeEndian::write_u16(buffer, *v),
            NetdevIndex(v) => NativeEndian::write_u32(buffer, *v),
            NetdevName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            PortFlavour(v) => NativeEndian::write_u16(buffer, *v),
            PortNumber(v) => NativeEndian::write_u32(buffer, *v),
            // Param(Vec<ParamAttr>),
            ParamName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            ParamGeneric(v) => buffer[0] = *v as u8,
            ParamType(v) => buffer[0] = *v,
            // ParamValueList(Vec<ParamAttr>),
            ParamValue(v) => NativeEndian::write_u64(buffer, *v),
            // ParamValueData(Vec<Vec<ParamAttr>>),
            ParamValueCmode(v) => buffer[0] = *v,
            RegionName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            RegionSize(v) => NativeEndian::write_u64(buffer, *v),
            // // RegionSnapshots(Vec<Vec<ParamAttr>>),
            // // RegionSnapshot(Vec<ParamAttr>),
            RegionSnapshotId(v) => NativeEndian::write_u32(buffer, *v),
            // // RegionChunks(Vec<Vec<ParamAttr>),
            // // RegionChunk(Vec<ParamAttr>),
            RegionChunkData(s) => {
                buffer[..s.len()].copy_from_slice(s);
            }
            RegionChunkOffset(v) => NativeEndian::write_u64(buffer, *v),
            RegionChunkSize(v) => NativeEndian::write_u64(buffer, *v),
            InfoDriverName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            InfoSerialNo(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            InfoVersionFixed(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            InfoVersionRunning(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            InfoVersionStored(nla) => {
                nla.iter().for_each(|val| val.emit_value(buffer));
            }
            InfoVersionName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            InfoVersionValue(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            FlashUpdateFileName(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            ReloadStatus(v) => buffer[0] = *v,
            ReloadAction(v) => buffer[0] = *v,
            Unknown(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for GenlDevlinkAttrs
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            DEVLINK_ATTR_BUS_NAME => Self::BusName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_BUS_NAME value")?,
            ),
            DEVLINK_ATTR_LOCATION => Self::Location(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_LOCATION value")?,
            ),
            DEVLINK_ATTR_PORT_INDEX => Self::PortIndex(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_PORT_INDEX value")?,
            ),
            DEVLINK_ATTR_PORT_TYPE => Self::PortType(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_PORT_TYPE value")?,
            ),
            DEVLINK_ATTR_DESIRED_TYPE => Self::DesiredType(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_DESIRED_TYPE value")?,
            ),
            DEVLINK_ATTR_NETDEV_IF_INDEX => Self::NetdevIndex(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_NETDEV_IF_INDEX value")?,
            ),
            DEVLINK_ATTR_NETDEV_NAME => Self::NetdevName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_NETDEV_NAME value")?,
            ),
            DEVLINK_ATTR_PORT_FLAVOUR => Self::PortFlavour(
                parse_u16(payload)
                    .context("invalid DEVLINK_ATTR_PORT_FLAVOUR value")?,
            ),
            DEVLINK_ATTR_PORT_NUMBER => Self::PortNumber(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_PORT_NUMBER value")?,
            ),
            //DEVLINK_ATTR_PARAM => Self::Param(/* nested */),
            DEVLINK_ATTR_PARAM_NAME => Self::ParamName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_PARAM_NAME value")?,
            ),
            DEVLINK_ATTR_PARAM_GENERIC => Self::ParamGeneric({
                let val = parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_PARAM_GENERIC value")?;
                if val == 0 {
                    false
                } else {
                    true
                }
            }),
            DEVLINK_ATTR_PARAM_TYPE => Self::ParamType(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_PARAM_TYPE value")?,
            ),
            //DEVLINK_ATTR_PARAM_VALUE_LIST => Self::ParamValueList(/* nested */),
            DEVLINK_ATTR_PARAM_VALUE => Self::ParamValue(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_PARAM_VALUE value")?,
            ),
            //DEVLINK_ATTR_PARAM_VALUE_DATA => Self::ParamValueData(/* dynaic */),
            DEVLINK_ATTR_PARAM_VALUE_CMODE => Self::ParamValueCmode(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_PARAM_VALUE_CMODE value")?,
            ),
            DEVLINK_ATTR_REGION_NAME => Self::RegionName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_REGION_NAME value")?,
            ),
            DEVLINK_ATTR_REGION_SIZE => Self::RegionSize(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_REGION_SIZE value")?,
            ),
            //DEVLINK_ATTR_REGION_SNAPSHOTS => Self::RegionSnapshots(/* nested */),
            //DEVLINK_ATTR_REGION_SNAPSHOT => Self::RegionSnapshot(/* nested */),
            DEVLINK_ATTR_REGION_SNAPSHOT_ID => Self::RegionSnapshotId(
                parse_u32(payload)
                    .context("invalid DEVLINK_ATTR_REGION_SNAPSHOT_ID value")?,
            ),
            //DEVLINK_ATTR_REGION_CHUNKS => Self::RegionChunks(/* nested */),
            //DEVLINK_ATTR_REGION_CHUNK => Self::RegionChunk(/* nested */),
            // DEVLINK_ATTR_REGION_CHUNK_DATA => Self::RegionChunkData(_),
            DEVLINK_ATTR_REGION_CHUNK_ADDR => Self::RegionChunkOffset(
                parse_u64(payload)
                    .context("invalid DEVLINK_ATTR_REGION_CHUNK_ADDR value")?,
            ),
            DEVLINK_ATTR_INFO_DRIVER_NAME => Self::InfoDriverName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_INFO_DRIVER_NAME value")?,
            ),
            DEVLINK_ATTR_INFO_SERIAL_NUMBER => Self::InfoSerialNo(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_INFO_SERIAL_NUMBER value")?,
            ),
            DEVLINK_ATTR_INFO_VERSION_FIXED => Self::InfoVersionFixed({
                let fixed = NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_INFO_VERSION_FIXED",
                    )?;
                fixed
            }),
            DEVLINK_ATTR_INFO_VERSION_RUNNING => Self::InfoVersionRunning({
                let running = NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_INFO_VERSION_RUNNING",
                    )?;
                running
            }),
            DEVLINK_ATTR_INFO_VERSION_STORED => Self::InfoVersionStored({
                let stored = NlasIterator::new(payload)
                    .map(|nla| {
                        nla.and_then(|nla| GenlDevlinkAttrs::parse(&nla))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .context(
                        "failed to parse DEVLINK_ATTR_INFO_VERSION_STORED",
                    )?;
                stored
            }),
            DEVLINK_ATTR_INFO_VERSION_NAME => Self::InfoVersionName(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_INFO_VERSION_NAME value")?),
            DEVLINK_ATTR_INFO_VERSION_VALUE => Self::InfoVersionValue(
                parse_string(payload)
                    .context("invalid DEVLINK_ATTR_INFO_VERSION_VALUE value")?),
            DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME => 
                Self::FlashUpdateFileName(parse_string(payload).context(
                    "invalid DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME value")?),
            DEVLINK_ATTR_RELOAD_FAILED => Self::ReloadStatus(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_RELOAD_FAILED value")?),
            DEVLINK_ATTR_RELOAD_ACTION => Self::ReloadAction(
                parse_u8(payload)
                    .context("invalid DEVLINK_ATTR_RELOAD_ACTION value")?),
            DEVLINK_ATTR_DEVICE_STATS => Self::Unknown("TBD - full stats parsin".to_string()), // TODO: implement
            _ => {
                return Err(DecodeError::from(format!(
                    "Unknown NLA type: {}",
                    buf.kind()
                )))
            }
        })
    }
}
