// SPDX-License-Identifier: MIT

use super::attr::{append_nl_string, parse_nl_string};
use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, Emitable,
    EncodeError, ErrorContext, Nla, NlaBuffer, Parseable,
};

const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

/// A nested multicast group entry in [`super::GenlCtrlAttr::McastGroups`].
///
/// `index` is the attribute type used by the kernel for the nested container.
/// The kernel numbers multicast groups starting from 1.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct GenlCtrlMcastGroupSet {
    pub index: u16,
    pub attrs: Vec<GenlCtrlMcastGroup>,
}

impl GenlCtrlMcastGroupSet {
    pub fn new(index: u16, attrs: Vec<GenlCtrlMcastGroup>) -> Self {
        Self { index, attrs }
    }
}

impl Nla for GenlCtrlMcastGroupSet {
    fn kind(&self) -> u16 {
        self.index
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.attrs.as_slice().emit(out)
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for GenlCtrlMcastGroupSet {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(Self {
            index: buf.kind(),
            attrs: Vec::<GenlCtrlMcastGroup>::parse(buf)
                .context("failed to parse multicast group")?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GenlCtrlMcastGroup {
    Name(String),
    Id(u32),
    Unknown(DefaultNla),
}

impl Nla for GenlCtrlMcastGroup {
    fn kind(&self) -> u16 {
        use GenlCtrlMcastGroup::*;
        match self {
            Name(_) => CTRL_ATTR_MCAST_GRP_NAME,
            Id(_) => CTRL_ATTR_MCAST_GRP_ID,
            Unknown(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use GenlCtrlMcastGroup::*;
        match self {
            Name(s) => append_nl_string(out, s)?,
            Id(v) => append_u32(out, *v),
            Unknown(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for GenlCtrlMcastGroup {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTRL_ATTR_MCAST_GRP_NAME => Self::Name(
                parse_nl_string(payload)
                    .context("invalid CTRL_ATTR_MCAST_GRP_NAME value")?,
            ),
            CTRL_ATTR_MCAST_GRP_ID => Self::Id(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_MCAST_GRP_ID value")?,
            ),
            _ => Self::Unknown(DefaultNla::parse(buf)?),
        })
    }
}
