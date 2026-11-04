// SPDX-License-Identifier: MIT

use crate::constants::*;
use netlink_packet_core::{
    append_u32, emit_nlas_into, parse_u32, DecodeError, EncodeError,
    ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OppolicyAttr {
    pub cmd: u8,
    pub policy_idx: Vec<OppolicyIndexAttr>,
}

impl Nla for OppolicyAttr {
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        emit_nlas_into(&self.policy_idx, out)
    }

    fn kind(&self) -> u16 {
        self.cmd as u16
    }

    fn is_nested(&self) -> bool {
        true
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for OppolicyAttr {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        let policy_idx = NlasIterator::new(payload)
            .map(|nla| nla.and_then(|nla| OppolicyIndexAttr::parse(&nla)))
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
    fn emit_value_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use OppolicyIndexAttr::*;
        match self {
            Do(v) => append_u32(out, *v),
            Dump(v) => append_u32(out, *v),
        }
        Ok(())
    }

    fn kind(&self) -> u16 {
        use OppolicyIndexAttr::*;
        match self {
            Do(_) => CTRL_ATTR_POLICY_DO,
            Dump(_) => CTRL_ATTR_POLICY_DUMP,
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for OppolicyIndexAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
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
