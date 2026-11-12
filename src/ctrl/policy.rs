// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_i64, append_u32, append_u64, parse_i64, parse_u32,
    parse_u64, DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext,
    Nla, NlaBuffer, Parseable,
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

const NL_POLICY_BYTE_ORDER_HOST: u32 = 0;
const NL_POLICY_BYTE_ORDER_BIG_ENDIAN: u32 = 1;

// GenlCtrlPolicySet

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenlCtrlPolicySet {
    pub index: u16,
    pub attrs: Vec<GenlCtrlPolicyEntry>,
}

impl Nla for GenlCtrlPolicySet {
    fn kind(&self) -> u16 {
        self.index
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.attrs.as_slice().emit(out)
    }

    fn is_nested(&self) -> bool {
        true
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for GenlCtrlPolicySet {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(Self {
            index: buf.kind(),
            attrs: Vec::<GenlCtrlPolicyEntry>::parse(buf)
                .context("failed to parse GenlCtrlPolicySet")?,
        })
    }
}

// GenlCtrlPolicyEntry

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenlCtrlPolicyEntry {
    pub index: u16,
    pub attrs: Vec<GenlCtrlPolicy>,
}

impl Nla for GenlCtrlPolicyEntry {
    fn kind(&self) -> u16 {
        self.index
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.attrs.as_slice().emit(out)
    }

    fn is_nested(&self) -> bool {
        true
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for GenlCtrlPolicyEntry {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        Ok(Self {
            index: buf.kind(),
            attrs: Vec::<GenlCtrlPolicy>::parse(buf)
                .context("failed to parse GenlCtrlPolicyEntry")?,
        })
    }
}

// GenlCtrlPolicy

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GenlCtrlPolicy {
    Type(GenlCtrlPolicyType),
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
    ByteOrder(GenlCtrlPolicyByteOrder),
    Unknown(DefaultNla),
}

/// Byte order of an integer policy attribute
/// (`enum netlink_policy_byte_order`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GenlCtrlPolicyByteOrder {
    /// Host byte order.
    Host,
    /// Big endian (network byte order).
    BigEndian,
    /// A byte order that is not known to this crate.
    Unknown(u32),
}

impl From<GenlCtrlPolicyByteOrder> for u32 {
    fn from(byte_order: GenlCtrlPolicyByteOrder) -> u32 {
        match byte_order {
            GenlCtrlPolicyByteOrder::Host => NL_POLICY_BYTE_ORDER_HOST,
            GenlCtrlPolicyByteOrder::BigEndian => {
                NL_POLICY_BYTE_ORDER_BIG_ENDIAN
            }
            GenlCtrlPolicyByteOrder::Unknown(value) => value,
        }
    }
}

impl TryFrom<u32> for GenlCtrlPolicyByteOrder {
    type Error = DecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            NL_POLICY_BYTE_ORDER_HOST => GenlCtrlPolicyByteOrder::Host,
            NL_POLICY_BYTE_ORDER_BIG_ENDIAN => {
                GenlCtrlPolicyByteOrder::BigEndian
            }
            value => GenlCtrlPolicyByteOrder::Unknown(value),
        })
    }
}

impl Nla for GenlCtrlPolicy {
    fn kind(&self) -> u16 {
        use GenlCtrlPolicy::*;
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
        use GenlCtrlPolicy::*;
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
            ByteOrder(v) => append_u32(out, u32::from(*v)),
            Unknown(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for GenlCtrlPolicy {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL_POLICY_TYPE_ATTR_TYPE => {
                let value = parse_u32(payload)
                    .context("invalid NL_POLICY_TYPE_ATTR_TYPE value")?;
                Self::Type(GenlCtrlPolicyType::try_from(value)?)
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
                GenlCtrlPolicyByteOrder::try_from(
                    parse_u32(payload).context(
                        "invalid NL_POLICY_TYPE_ATTR_BYTE_ORDER value",
                    )?,
                )
                .context("invalid NL_POLICY_TYPE_ATTR_BYTE_ORDER value")?,
            ),
            _ => Self::Unknown(DefaultNla::parse(buf)?),
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GenlCtrlPolicyType {
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

impl From<GenlCtrlPolicyType> for u32 {
    fn from(policy_type: GenlCtrlPolicyType) -> u32 {
        match policy_type {
            GenlCtrlPolicyType::Invalid => NL_ATTR_TYPE_INVALID,
            GenlCtrlPolicyType::Flag => NL_ATTR_TYPE_FLAG,
            GenlCtrlPolicyType::U8 => NL_ATTR_TYPE_U8,
            GenlCtrlPolicyType::U16 => NL_ATTR_TYPE_U16,
            GenlCtrlPolicyType::U32 => NL_ATTR_TYPE_U32,
            GenlCtrlPolicyType::U64 => NL_ATTR_TYPE_U64,
            GenlCtrlPolicyType::S8 => NL_ATTR_TYPE_S8,
            GenlCtrlPolicyType::S16 => NL_ATTR_TYPE_S16,
            GenlCtrlPolicyType::S32 => NL_ATTR_TYPE_S32,
            GenlCtrlPolicyType::S64 => NL_ATTR_TYPE_S64,
            GenlCtrlPolicyType::Binary => NL_ATTR_TYPE_BINARY,
            GenlCtrlPolicyType::String => NL_ATTR_TYPE_STRING,
            GenlCtrlPolicyType::NulString => NL_ATTR_TYPE_NUL_STRING,
            GenlCtrlPolicyType::Nested => NL_ATTR_TYPE_NESTED,
            GenlCtrlPolicyType::NestedArray => NL_ATTR_TYPE_NESTED_ARRAY,
            GenlCtrlPolicyType::Bitfield32 => NL_ATTR_TYPE_BITFIELD32,
            GenlCtrlPolicyType::SInt => NL_ATTR_TYPE_SINT,
            GenlCtrlPolicyType::UInt => NL_ATTR_TYPE_UINT,
            GenlCtrlPolicyType::Unknown(value) => value,
        }
    }
}

impl TryFrom<u32> for GenlCtrlPolicyType {
    type Error = DecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            NL_ATTR_TYPE_INVALID => GenlCtrlPolicyType::Invalid,
            NL_ATTR_TYPE_FLAG => GenlCtrlPolicyType::Flag,
            NL_ATTR_TYPE_U8 => GenlCtrlPolicyType::U8,
            NL_ATTR_TYPE_U16 => GenlCtrlPolicyType::U16,
            NL_ATTR_TYPE_U32 => GenlCtrlPolicyType::U32,
            NL_ATTR_TYPE_U64 => GenlCtrlPolicyType::U64,
            NL_ATTR_TYPE_S8 => GenlCtrlPolicyType::S8,
            NL_ATTR_TYPE_S16 => GenlCtrlPolicyType::S16,
            NL_ATTR_TYPE_S32 => GenlCtrlPolicyType::S32,
            NL_ATTR_TYPE_S64 => GenlCtrlPolicyType::S64,
            NL_ATTR_TYPE_BINARY => GenlCtrlPolicyType::Binary,
            NL_ATTR_TYPE_STRING => GenlCtrlPolicyType::String,
            NL_ATTR_TYPE_NUL_STRING => GenlCtrlPolicyType::NulString,
            NL_ATTR_TYPE_NESTED => GenlCtrlPolicyType::Nested,
            NL_ATTR_TYPE_NESTED_ARRAY => GenlCtrlPolicyType::NestedArray,
            NL_ATTR_TYPE_BITFIELD32 => GenlCtrlPolicyType::Bitfield32,
            NL_ATTR_TYPE_SINT => GenlCtrlPolicyType::SInt,
            NL_ATTR_TYPE_UINT => GenlCtrlPolicyType::UInt,
            value => GenlCtrlPolicyType::Unknown(value),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_min_max_kinds() {
        assert_eq!(
            GenlCtrlPolicy::MinValueUnsigned(0).kind(),
            NL_POLICY_TYPE_ATTR_MIN_VALUE_U
        );
        assert_eq!(
            GenlCtrlPolicy::MaxValueUnsigned(0).kind(),
            NL_POLICY_TYPE_ATTR_MAX_VALUE_U
        );
    }
}
