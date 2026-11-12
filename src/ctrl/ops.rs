// SPDX-License-Identifier: MIT

use super::attr::checked_index;
use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, Emitable,
    EncodeError, ErrorContext, Nla, NlaBuffer, Parseable,
};
use std::ops::Deref;

const CTRL_ATTR_OP_ID: u16 = 1;
const CTRL_ATTR_OP_FLAGS: u16 = 2;

pub(crate) struct OpList(Vec<Op>);

impl Deref for OpList {
    type Target = Vec<Op>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&Vec<Vec<OpAttrs>>> for OpList {
    type Error = EncodeError;

    fn try_from(ops: &Vec<Vec<OpAttrs>>) -> Result<Self, Self::Error> {
        Ok(Self(
            ops.iter()
                .cloned()
                .enumerate()
                .map(|(index, nlas)| {
                    Ok(Op {
                        index: checked_index(index)?,
                        nlas,
                    })
                })
                .collect::<Result<Vec<_>, EncodeError>>()?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Op {
    pub(crate) index: u16,
    pub(crate) nlas: Vec<OpAttrs>,
}

impl Nla for Op {
    fn kind(&self) -> u16 {
        self.index + 1
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.nlas.as_slice().emit(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpAttrs {
    Id(u32),
    Flags(u32),
    Unknown(DefaultNla),
}

impl Nla for OpAttrs {
    fn kind(&self) -> u16 {
        use OpAttrs::*;
        match self {
            Id(_) => CTRL_ATTR_OP_ID,
            Flags(_) => CTRL_ATTR_OP_FLAGS,
            Unknown(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use OpAttrs::*;
        match self {
            Id(v) => append_u32(out, *v),
            Flags(v) => append_u32(out, *v),
            Unknown(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for OpAttrs {
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
