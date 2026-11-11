// SPDX-License-Identifier: MIT

//! header definition of generic netlink packet
use netlink_packet_core::{append_bytes, DecodeError, Emitable, EncodeError};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub(crate) const GENL_HDRLEN: usize = 4;

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

impl Emitable for GenlHeader {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let raw = GenlHeaderBuffer::from(self);
        append_bytes(out, raw.as_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let header = GenlHeader { cmd: 7, version: 3 };
        let mut buf = Vec::new();
        header.emit(&mut buf).unwrap();

        assert_eq!(buf, [7, 3, 0, 0]);
        assert_eq!(GenlHeader::parse(&buf).unwrap(), header);
    }

    #[test]
    fn header_parse_too_short() {
        let err = GenlHeader::parse(&[1, 2, 3]).unwrap_err();
        assert!(err.is_buffer_too_small());
    }

    #[test]
    fn header_ignores_reserved_bytes() {
        let header = GenlHeader::parse(&[1, 2, 0xff, 0xff]).unwrap();
        assert_eq!(header, GenlHeader { cmd: 1, version: 2 });
    }
}
