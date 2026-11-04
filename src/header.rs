// SPDX-License-Identifier: MIT

//! header definition of generic netlink packet
use crate::constants::GENL_HDRLEN;
use netlink_packet_core::DecodeError;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Generic Netlink header
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenlHeader {
    pub cmd: u8,
    pub version: u8,
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C, packed)]
pub(crate) struct GenlHeaderBuffer {
    cmd: u8,
    version: u8,
    reserved: u16,
}

impl ::netlink_packet_core::Emitable for GenlHeader {
    fn emit_into(
        &self,
        out: &mut Vec<u8>,
    ) -> Result<(), ::netlink_packet_core::EncodeError> {
        let raw = GenlHeaderBuffer::from(self);
        out.extend_from_slice(raw.as_bytes());
        Ok(())
    }
}

impl GenlHeader {
    pub fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let (raw, _) =
            GenlHeaderBuffer::ref_from_prefix(payload).map_err(|_| {
                DecodeError::buffer_too_small(payload.len(), GENL_HDRLEN)
            })?;
        Ok(Self {
            cmd: raw.cmd,
            version: raw.version,
        })
    }
}

impl From<&GenlHeader> for GenlHeaderBuffer {
    fn from(header: &GenlHeader) -> Self {
        Self {
            cmd: header.cmd,
            version: header.version,
            // The kernel expects the reserved field to always be zero.
            reserved: 0,
        }
    }
}
