// SPDX-License-Identifier: MIT

use crate::constants::*;
use netlink_packet_core::{
    append_u32, parse_u32, DecodeError, Emitable, EncodeError, ErrorContext,
    Nla, NlaBuffer, NlasIterator, Parseable,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OppolicyAttr {
    pub cmd: u8,
    pub policy_idx: Vec<OppolicyIndexAttr>,
}

impl Nla for OppolicyAttr {
    fn kind(&self) -> u16 {
        self.cmd as u16
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.policy_idx.as_slice().emit(out)
    }

    fn is_nested(&self) -> bool {
        true
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for OppolicyAttr {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let policy_idx = NlasIterator::new(buf.value())?
            .map(|nla| OppolicyIndexAttr::parse(&nla))
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse OppolicyAttr")?;

        Ok(Self {
            cmd: buf.kind() as u8,
            policy_idx,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OppolicyIndexAttr {
    Do(u32),
    Dump(u32),
}

impl Nla for OppolicyIndexAttr {
    fn kind(&self) -> u16 {
        use OppolicyIndexAttr::*;
        match self {
            Do(_) => CTRL_ATTR_POLICY_DO,
            Dump(_) => CTRL_ATTR_POLICY_DUMP,
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use OppolicyIndexAttr::*;
        match self {
            Do(v) => append_u32(out, *v),
            Dump(v) => append_u32(out, *v),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for OppolicyIndexAttr {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTRL_ATTR_POLICY_DO => Self::Do(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_POLICY_DO value")?,
            ),
            CTRL_ATTR_POLICY_DUMP => Self::Dump(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_POLICY_DUMP value")?,
            ),
            kind => {
                return Err(DecodeError::from(format!(
                    "Unknown NLA type: {kind}"
                )))
            }
        })
    }
}
