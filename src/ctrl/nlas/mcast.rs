// SPDX-License-Identifier: MIT

use super::append_nl_string;
use crate::constants::*;
use netlink_packet_core::{
    append_u32, parse_string, parse_u32, DecodeError, Emitable, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};
use std::ops::Deref;

pub(crate) struct McastGroupList(Vec<McastGroup>);

impl Deref for McastGroupList {
    type Target = Vec<McastGroup>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&Vec<Vec<McastGrpAttrs>>> for McastGroupList {
    fn from(groups: &Vec<Vec<McastGrpAttrs>>) -> Self {
        Self(
            groups
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, nlas)| McastGroup {
                    index: index as u16,
                    nlas,
                })
                .collect(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McastGroup {
    pub index: u16,
    pub nlas: Vec<McastGrpAttrs>,
}

impl Nla for McastGroup {
    fn kind(&self) -> u16 {
        self.index + 1
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.nlas.as_slice().emit(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McastGrpAttrs {
    Name(String),
    Id(u32),
}

impl Nla for McastGrpAttrs {
    fn kind(&self) -> u16 {
        use McastGrpAttrs::*;
        match self {
            Name(_) => CTRL_ATTR_MCAST_GRP_NAME,
            Id(_) => CTRL_ATTR_MCAST_GRP_ID,
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use McastGrpAttrs::*;
        match self {
            Name(s) => append_nl_string(out, s)?,
            Id(v) => append_u32(out, *v),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for McastGrpAttrs {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTRL_ATTR_MCAST_GRP_NAME => Self::Name(
                parse_string(payload)
                    .context("invalid CTRL_ATTR_MCAST_GRP_NAME value")?,
            ),
            CTRL_ATTR_MCAST_GRP_ID => Self::Id(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_MCAST_GRP_ID value")?,
            ),
            kind => {
                return Err(DecodeError::from(format!(
                    "Unknown NLA type: {kind}"
                )))
            }
        })
    }
}
