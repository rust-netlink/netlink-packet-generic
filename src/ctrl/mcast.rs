// SPDX-License-Identifier: MIT

use super::attr::{append_nl_string, checked_index};
use netlink_packet_core::{
    append_bytes, append_u32, parse_string, parse_u32, DecodeError, DefaultNla,
    Emitable, EncodeError, ErrorContext, Nla, NlaBuffer, Parseable,
};
use std::ops::Deref;

const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

pub(crate) struct McastGroupList(Vec<McastGroup>);

impl Deref for McastGroupList {
    type Target = Vec<McastGroup>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&Vec<Vec<McastGrpAttrs>>> for McastGroupList {
    type Error = EncodeError;

    fn try_from(groups: &Vec<Vec<McastGrpAttrs>>) -> Result<Self, Self::Error> {
        Ok(Self(
            groups
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, nlas)| {
                    Ok(McastGroup {
                        index: checked_index(index)?,
                        nlas,
                    })
                })
                .collect::<Result<Vec<_>, EncodeError>>()?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct McastGroup {
    index: u16,
    nlas: Vec<McastGrpAttrs>,
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
#[non_exhaustive]
pub enum McastGrpAttrs {
    Name(String),
    Id(u32),
    Unknown(DefaultNla),
}

impl Nla for McastGrpAttrs {
    fn kind(&self) -> u16 {
        use McastGrpAttrs::*;
        match self {
            Name(_) => CTRL_ATTR_MCAST_GRP_NAME,
            Id(_) => CTRL_ATTR_MCAST_GRP_ID,
            Unknown(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use McastGrpAttrs::*;
        match self {
            Name(s) => append_nl_string(out, s)?,
            Id(v) => append_u32(out, *v),
            Unknown(nla) => append_bytes(out, nla.value()),
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
            _ => Self::Unknown(DefaultNla::parse(buf)?),
        })
    }
}
