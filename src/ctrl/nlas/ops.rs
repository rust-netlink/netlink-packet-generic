// SPDX-License-Identifier: MIT

use crate::constants::*;
use netlink_packet_core::{
    append_u32, emit_nlas_into, parse_u32, DecodeError, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

use std::ops::Deref;

pub struct OpList(Vec<Op>);

impl Deref for OpList {
    type Target = Vec<Op>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&Vec<Vec<OpAttrs>>> for OpList {
    fn from(ops: &Vec<Vec<OpAttrs>>) -> Self {
        Self(
            ops.iter()
                .cloned()
                .enumerate()
                .map(|(index, nlas)| Op {
                    index: index as u16,
                    nlas,
                })
                .collect(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub index: u16,
    pub nlas: Vec<OpAttrs>,
}

impl Nla for Op {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        emit_nlas_into(&self.nlas, out)
    }

    fn kind(&self) -> u16 {
        self.index + 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpAttrs {
    Id(u32),
    Flags(u32),
}

impl Nla for OpAttrs {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use OpAttrs::*;
        match self {
            Id(v) => append_u32(out, *v),
            Flags(v) => append_u32(out, *v),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        use OpAttrs::*;
        match self {
            Id(_) => CTRL_ATTR_OP_ID,
            Flags(_) => CTRL_ATTR_OP_FLAGS,
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for OpAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTRL_ATTR_OP_ID => Self::Id(
                parse_u32(payload).context("invalid CTRL_ATTR_OP_ID value")?,
            ),
            CTRL_ATTR_OP_FLAGS => Self::Flags(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_OP_FLAGS value")?,
            ),
            kind => {
                return Err(DecodeError::from(format!(
                    "Unknown NLA type: {kind}"
                )))
            }
        })
    }
}
