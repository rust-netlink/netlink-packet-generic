// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_i64, append_u32, append_u64, append_u8, parse_i64,
    parse_i8, parse_u32, parse_u64, DecodeError, DefaultNla, Emitable,
    EncodeError, ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable,
};
use std::convert::TryFrom;

const NL_ATTR_TYPE_INVALID: u32 = 0;
const NL_ATTR_TYPE_FLAG: u32 = 1;
const NL_ATTR_TYPE_U8: u32 = 2;
const NL_ATTR_TYPE_U16: u32 = 3;
const NL_ATTR_TYPE_U32: u32 = 4;
const NL_ATTR_TYPE_U64: u32 = 5;
const NL_ATTR_TYPE_S8: u32 = 6;
const NL_ATTR_TYPE_S16: u32 = 7;
const NL_ATTR_TYPE_S32: u32 = 8;
const NL_ATTR_TYPE_S64: u32 = 9;
const NL_ATTR_TYPE_BINARY: u32 = 10;
const NL_ATTR_TYPE_STRING: u32 = 11;
const NL_ATTR_TYPE_NUL_STRING: u32 = 12;
const NL_ATTR_TYPE_NESTED: u32 = 13;
const NL_ATTR_TYPE_NESTED_ARRAY: u32 = 14;
const NL_ATTR_TYPE_BITFIELD32: u32 = 15;
const NL_ATTR_TYPE_SINT: u32 = 16;
const NL_ATTR_TYPE_UINT: u32 = 17;

const NL_POLICY_TYPE_ATTR_TYPE: u16 = 1;
const NL_POLICY_TYPE_ATTR_MIN_VALUE_S: u16 = 2;
const NL_POLICY_TYPE_ATTR_MAX_VALUE_S: u16 = 3;
const NL_POLICY_TYPE_ATTR_MIN_VALUE_U: u16 = 4;
const NL_POLICY_TYPE_ATTR_MAX_VALUE_U: u16 = 5;
const NL_POLICY_TYPE_ATTR_MIN_LENGTH: u16 = 6;
const NL_POLICY_TYPE_ATTR_MAX_LENGTH: u16 = 7;
const NL_POLICY_TYPE_ATTR_POLICY_IDX: u16 = 8;
const NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE: u16 = 9;
const NL_POLICY_TYPE_ATTR_BITFIELD32_MASK: u16 = 10;
const NL_POLICY_TYPE_ATTR_MASK: u16 = 12;
const NL_POLICY_TYPE_ATTR_BYTE_ORDER: u16 = 13;

// PolicyAttr

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyAttr {
    pub index: u16,
    pub attr_policy: AttributePolicyAttr,
}

impl Nla for PolicyAttr {
    fn kind(&self) -> u16 {
        self.index
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.attr_policy.emit(out)
    }

    fn is_nested(&self) -> bool {
        true
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for PolicyAttr {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(Self {
            index: buf.kind(),
            attr_policy: AttributePolicyAttr::parse(
                &NlaBuffer::new(buf.value())
                    .context("failed to parse PolicyAttr")?,
            )
            .context("failed to parse PolicyAttr")?,
        })
    }
}

// AttributePolicyAttr

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributePolicyAttr {
    pub index: u16,
    pub policies: Vec<NlPolicyTypeAttrs>,
}

impl Nla for AttributePolicyAttr {
    fn kind(&self) -> u16 {
        self.index
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.policies.as_slice().emit(out)
    }

    fn is_nested(&self) -> bool {
        true
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for AttributePolicyAttr {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let policies = NlasIterator::new(buf.value())?
            .map(|nla| NlPolicyTypeAttrs::parse(&nla))
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse AttributePolicyAttr")?;

        Ok(Self {
            index: buf.kind(),
            policies,
        })
    }
}

// PolicyTypeAttrs

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NlPolicyTypeAttrs {
    Type(NlaType),
    MinValueSigned(i64),
    MaxValueSigned(i64),
    MaxValueUnsigned(u64),
    MinValueUnsigned(u64),
    MinLength(u32),
    MaxLength(u32),
    PolicyIdx(u32),
    PolicyMaxType(u32),
    Bitfield32Mask(u32),
    Mask(u64),
    ByteOrder(i8),
    Unknown(DefaultNla),
}

impl Nla for NlPolicyTypeAttrs {
    fn kind(&self) -> u16 {
        use NlPolicyTypeAttrs::*;
        match self {
            Type(_) => NL_POLICY_TYPE_ATTR_TYPE,
            MinValueSigned(_) => NL_POLICY_TYPE_ATTR_MIN_VALUE_S,
            MaxValueSigned(_) => NL_POLICY_TYPE_ATTR_MAX_VALUE_S,
            MaxValueUnsigned(_) => NL_POLICY_TYPE_ATTR_MAX_VALUE_U,
            MinValueUnsigned(_) => NL_POLICY_TYPE_ATTR_MIN_VALUE_U,
            MinLength(_) => NL_POLICY_TYPE_ATTR_MIN_LENGTH,
            MaxLength(_) => NL_POLICY_TYPE_ATTR_MAX_LENGTH,
            PolicyIdx(_) => NL_POLICY_TYPE_ATTR_POLICY_IDX,
            PolicyMaxType(_) => NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE,
            Bitfield32Mask(_) => NL_POLICY_TYPE_ATTR_BITFIELD32_MASK,
            Mask(_) => NL_POLICY_TYPE_ATTR_MASK,
            ByteOrder(_) => NL_POLICY_TYPE_ATTR_BYTE_ORDER,
            Unknown(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use NlPolicyTypeAttrs::*;
        match self {
            Type(v) => append_u32(out, u32::from(*v)),
            MinValueSigned(v) => append_i64(out, *v),
            MaxValueSigned(v) => append_i64(out, *v),
            MaxValueUnsigned(v) => append_u64(out, *v),
            MinValueUnsigned(v) => append_u64(out, *v),
            MinLength(v) => append_u32(out, *v),
            MaxLength(v) => append_u32(out, *v),
            PolicyIdx(v) => append_u32(out, *v),
            PolicyMaxType(v) => append_u32(out, *v),
            Bitfield32Mask(v) => append_u32(out, *v),
            Mask(v) => append_u64(out, *v),
            ByteOrder(v) => append_u8(out, *v as u8),
            Unknown(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for NlPolicyTypeAttrs {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL_POLICY_TYPE_ATTR_TYPE => {
                let value = parse_u32(payload)
                    .context("invalid NL_POLICY_TYPE_ATTR_TYPE value")?;
                Self::Type(NlaType::try_from(value)?)
            }
            NL_POLICY_TYPE_ATTR_MIN_VALUE_S => Self::MinValueSigned(
                parse_i64(payload)
                    .context("invalid NL_POLICY_TYPE_ATTR_MIN_VALUE_S value")?,
            ),
            NL_POLICY_TYPE_ATTR_MAX_VALUE_S => Self::MaxValueSigned(
                parse_i64(payload)
                    .context("invalid NL_POLICY_TYPE_ATTR_MAX_VALUE_S value")?,
            ),
            NL_POLICY_TYPE_ATTR_MIN_VALUE_U => Self::MinValueUnsigned(
                parse_u64(payload)
                    .context("invalid NL_POLICY_TYPE_ATTR_MIN_VALUE_U value")?,
            ),
            NL_POLICY_TYPE_ATTR_MAX_VALUE_U => Self::MaxValueUnsigned(
                parse_u64(payload)
                    .context("invalid NL_POLICY_TYPE_ATTR_MAX_VALUE_U value")?,
            ),
            NL_POLICY_TYPE_ATTR_MIN_LENGTH => Self::MinLength(
                parse_u32(payload)
                    .context("invalid NL_POLICY_TYPE_ATTR_MIN_LENGTH value")?,
            ),
            NL_POLICY_TYPE_ATTR_MAX_LENGTH => Self::MaxLength(
                parse_u32(payload)
                    .context("invalid NL_POLICY_TYPE_ATTR_MAX_LENGTH value")?,
            ),
            NL_POLICY_TYPE_ATTR_POLICY_IDX => Self::PolicyIdx(
                parse_u32(payload)
                    .context("invalid NL_POLICY_TYPE_ATTR_POLICY_IDX value")?,
            ),
            NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE => {
                Self::PolicyMaxType(parse_u32(payload).context(
                    "invalid NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE value",
                )?)
            }
            NL_POLICY_TYPE_ATTR_BITFIELD32_MASK => {
                Self::Bitfield32Mask(parse_u32(payload).context(
                    "invalid NL_POLICY_TYPE_ATTR_BITFIELD32_MASK value",
                )?)
            }
            NL_POLICY_TYPE_ATTR_MASK => Self::Mask(
                parse_u64(payload)
                    .context("invalid NL_POLICY_TYPE_ATTR_MASK value")?,
            ),
            NL_POLICY_TYPE_ATTR_BYTE_ORDER => Self::ByteOrder(
                parse_i8(payload)
                    .context("invalid NL_POLICY_TYPE_ATTR_BYTE_ORDER value")?,
            ),
            _ => Self::Unknown(DefaultNla::parse(buf)?),
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NlaType {
    Invalid,
    Flag,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    Binary,
    String,
    NulString,
    Nested,
    NestedArray,
    Bitfield32,
    SInt,
    UInt,
    Unknown(u32),
}

impl From<NlaType> for u32 {
    fn from(nlatype: NlaType) -> u32 {
        match nlatype {
            NlaType::Invalid => NL_ATTR_TYPE_INVALID,
            NlaType::Flag => NL_ATTR_TYPE_FLAG,
            NlaType::U8 => NL_ATTR_TYPE_U8,
            NlaType::U16 => NL_ATTR_TYPE_U16,
            NlaType::U32 => NL_ATTR_TYPE_U32,
            NlaType::U64 => NL_ATTR_TYPE_U64,
            NlaType::S8 => NL_ATTR_TYPE_S8,
            NlaType::S16 => NL_ATTR_TYPE_S16,
            NlaType::S32 => NL_ATTR_TYPE_S32,
            NlaType::S64 => NL_ATTR_TYPE_S64,
            NlaType::Binary => NL_ATTR_TYPE_BINARY,
            NlaType::String => NL_ATTR_TYPE_STRING,
            NlaType::NulString => NL_ATTR_TYPE_NUL_STRING,
            NlaType::Nested => NL_ATTR_TYPE_NESTED,
            NlaType::NestedArray => NL_ATTR_TYPE_NESTED_ARRAY,
            NlaType::Bitfield32 => NL_ATTR_TYPE_BITFIELD32,
            NlaType::SInt => NL_ATTR_TYPE_SINT,
            NlaType::UInt => NL_ATTR_TYPE_UINT,
            NlaType::Unknown(value) => value,
        }
    }
}

impl TryFrom<u32> for NlaType {
    type Error = DecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            NL_ATTR_TYPE_INVALID => NlaType::Invalid,
            NL_ATTR_TYPE_FLAG => NlaType::Flag,
            NL_ATTR_TYPE_U8 => NlaType::U8,
            NL_ATTR_TYPE_U16 => NlaType::U16,
            NL_ATTR_TYPE_U32 => NlaType::U32,
            NL_ATTR_TYPE_U64 => NlaType::U64,
            NL_ATTR_TYPE_S8 => NlaType::S8,
            NL_ATTR_TYPE_S16 => NlaType::S16,
            NL_ATTR_TYPE_S32 => NlaType::S32,
            NL_ATTR_TYPE_S64 => NlaType::S64,
            NL_ATTR_TYPE_BINARY => NlaType::Binary,
            NL_ATTR_TYPE_STRING => NlaType::String,
            NL_ATTR_TYPE_NUL_STRING => NlaType::NulString,
            NL_ATTR_TYPE_NESTED => NlaType::Nested,
            NL_ATTR_TYPE_NESTED_ARRAY => NlaType::NestedArray,
            NL_ATTR_TYPE_BITFIELD32 => NlaType::Bitfield32,
            NL_ATTR_TYPE_SINT => NlaType::SInt,
            NL_ATTR_TYPE_UINT => NlaType::UInt,
            value => NlaType::Unknown(value),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_min_max_kinds() {
        assert_eq!(
            NlPolicyTypeAttrs::MinValueUnsigned(0).kind(),
            NL_POLICY_TYPE_ATTR_MIN_VALUE_U
        );
        assert_eq!(
            NlPolicyTypeAttrs::MaxValueUnsigned(0).kind(),
            NL_POLICY_TYPE_ATTR_MAX_VALUE_U
        );
    }
}
