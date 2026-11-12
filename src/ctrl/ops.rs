// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, Emitable,
    EncodeError, ErrorContext, Nla, NlaBuffer, Parseable,
};

const CTRL_ATTR_OP_ID: u16 = 1;
const CTRL_ATTR_OP_FLAGS: u16 = 2;

/// A nested operation entry in [`super::GenlCtrlAttr::Ops`].
///
/// `index` is the attribute type used by the kernel for the nested container.
/// The kernel numbers operations starting from 1.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct GenlCtrlOpSet {
    pub index: u16,
    pub attrs: Vec<GenlCtrlOp>,
}

impl GenlCtrlOpSet {
    pub fn new(index: u16, attrs: Vec<GenlCtrlOp>) -> Self {
        Self { index, attrs }
    }
}

impl Nla for GenlCtrlOpSet {
    fn kind(&self) -> u16 {
        self.index
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.attrs.as_slice().emit(out)
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for GenlCtrlOpSet {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(Self {
            index: buf.kind(),
            attrs: Vec::<GenlCtrlOp>::parse(buf)
                .context("failed to parse generic netlink operation")?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GenlCtrlOp {
    Id(u32),
    Flags(u32),
    Unknown(DefaultNla),
}

impl Nla for GenlCtrlOp {
    fn kind(&self) -> u16 {
        use GenlCtrlOp::*;
        match self {
            Id(_) => CTRL_ATTR_OP_ID,
            Flags(_) => CTRL_ATTR_OP_FLAGS,
            Unknown(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use GenlCtrlOp::*;
        match self {
            Id(v) => append_u32(out, *v),
            Flags(v) => append_u32(out, *v),
            Unknown(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for GenlCtrlOp {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTRL_ATTR_OP_ID => Self::Id(
                parse_u32(payload).context("invalid CTRL_ATTR_OP_ID value")?,
            ),
            CTRL_ATTR_OP_FLAGS => Self::Flags(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_OP_FLAGS value")?,
            ),
            _ => Self::Unknown(DefaultNla::parse(buf)?),
        })
    }
}
