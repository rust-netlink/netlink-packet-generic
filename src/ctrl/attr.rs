// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u16, append_u32, parse_string, parse_u16, parse_u32,
    DecodeError, DefaultNla, Emitable, EncodeError, EncodeErrorKind,
    ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable, NLA_F_NESTED,
};

use super::mcast::GenlCtrlMcastGroupSet;
use super::oppolicy::GenlCtrlOpPolicy;
use super::ops::GenlCtrlOpSet;
use super::policy::GenlCtrlPolicySet;

const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_VERSION: u16 = 3;
const CTRL_ATTR_HDRSIZE: u16 = 4;
const CTRL_ATTR_MAXATTR: u16 = 5;
const CTRL_ATTR_OPS: u16 = 6;
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
const CTRL_ATTR_POLICY: u16 = 8;
const CTRL_ATTR_OP_POLICY: u16 = 9;
const CTRL_ATTR_OP: u16 = 10;

/// Length of a generic netlink family or multicast group name, including the
/// trailing NUL (`GENL_NAMSIZ` in `include/uapi/linux/genetlink.h`).
pub(crate) const GENL_NAMSIZ: usize = 16;

/// Append a NUL-terminated netlink string.
///
/// Interior NUL bytes are rejected because they would make parsing stop
/// early and turn the emit/parse round trip lossy.
///
/// The kernel stores both family names (`genl_family::name`) and multicast
/// group names (`genl_multicast_group::name`) in a `char[GENL_NAMSIZ]`
/// buffer, and validates `CTRL_ATTR_FAMILY_NAME` with `.len = GENL_NAMSIZ -
/// 1`. Reject longer values here so the crate cannot emit a controller
/// message the kernel would consider invalid.
pub(crate) fn append_nl_string(
    out: &mut Vec<u8>,
    value: &str,
) -> Result<(), EncodeError> {
    if value.as_bytes().contains(&0) {
        return Err(EncodeError::new(
            EncodeErrorKind::InvalidValue,
            format!("netlink string contains an interior NUL byte: {value:?}"),
        ));
    }
    if value.len() >= GENL_NAMSIZ {
        return Err(EncodeError::too_large(format!(
            "generic netlink name is too long: {} >= {GENL_NAMSIZ}",
            value.len()
        )));
    }
    append_bytes(out, value.as_bytes());
    out.push(0);
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GenlCtrlAttr {
    FamilyId(u16),
    FamilyName(String),
    Version(u32),
    HdrSize(u32),
    MaxAttr(u32),
    Ops(Vec<GenlCtrlOpSet>),
    McastGroups(Vec<GenlCtrlMcastGroupSet>),
    Policy(Vec<GenlCtrlPolicySet>),
    OpPolicy(Vec<GenlCtrlOpPolicy>),
    Op(u32),
    Unknown(DefaultNla),
}

impl Nla for GenlCtrlAttr {
    fn kind(&self) -> u16 {
        use GenlCtrlAttr::*;
        match self {
            FamilyId(_) => CTRL_ATTR_FAMILY_ID,
            FamilyName(_) => CTRL_ATTR_FAMILY_NAME,
            Version(_) => CTRL_ATTR_VERSION,
            HdrSize(_) => CTRL_ATTR_HDRSIZE,
            MaxAttr(_) => CTRL_ATTR_MAXATTR,
            Ops(_) => CTRL_ATTR_OPS,
            McastGroups(_) => CTRL_ATTR_MCAST_GROUPS,
            Policy(_) => CTRL_ATTR_POLICY,
            OpPolicy(_) => CTRL_ATTR_OP_POLICY,
            Op(_) => CTRL_ATTR_OP,
            Unknown(nla) => nla.kind(),
        }
    }

    fn is_nested(&self) -> bool {
        match self {
            // The kernel marks CTRL_ATTR_POLICY and CTRL_ATTR_OP_POLICY as
            // nested, but intentionally leaves CTRL_ATTR_OPS and
            // CTRL_ATTR_MCAST_GROUPS unmarked.
            Self::Policy(_) | Self::OpPolicy(_) => true,
            _ => self.kind() & NLA_F_NESTED != 0,
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use GenlCtrlAttr::*;
        match self {
            FamilyId(v) => append_u16(out, *v),
            FamilyName(s) => append_nl_string(out, s)?,
            Version(v) => append_u32(out, *v),
            HdrSize(v) => append_u32(out, *v),
            MaxAttr(v) => append_u32(out, *v),
            Ops(nlas) => nlas.as_slice().emit(out)?,
            McastGroups(nlas) => nlas.as_slice().emit(out)?,
            Policy(nlas) => nlas.as_slice().emit(out)?,
            OpPolicy(nlas) => nlas.as_slice().emit(out)?,
            Op(v) => append_u32(out, *v),
            Unknown(nla) => append_bytes(out, nla.value()),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for GenlCtrlAttr {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            CTRL_ATTR_FAMILY_ID => Self::FamilyId(
                parse_u16(payload)
                    .context("invalid CTRL_ATTR_FAMILY_ID value")?,
            ),
            CTRL_ATTR_FAMILY_NAME => Self::FamilyName(
                parse_string(payload)
                    .context("invalid CTRL_ATTR_FAMILY_NAME value")?,
            ),
            CTRL_ATTR_VERSION => Self::Version(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_VERSION value")?,
            ),
            CTRL_ATTR_HDRSIZE => Self::HdrSize(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_HDRSIZE value")?,
            ),
            CTRL_ATTR_MAXATTR => Self::MaxAttr(
                parse_u32(payload)
                    .context("invalid CTRL_ATTR_MAXATTR value")?,
            ),
            CTRL_ATTR_OPS => {
                let ops = NlasIterator::new(payload)?
                    .map(|nla| GenlCtrlOpSet::parse(&nla))
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse CTRL_ATTR_OPS")?;
                Self::Ops(ops)
            }
            CTRL_ATTR_MCAST_GROUPS => {
                let groups = NlasIterator::new(payload)?
                    .map(|nla| GenlCtrlMcastGroupSet::parse(&nla))
                    .collect::<Result<Vec<_>, _>>()
                    .context("failed to parse CTRL_ATTR_MCAST_GROUPS")?;
                Self::McastGroups(groups)
            }
            CTRL_ATTR_POLICY => Self::Policy(
                Vec::<GenlCtrlPolicySet>::parse(payload)
                    .context("failed to parse CTRL_ATTR_POLICY")?,
            ),
            CTRL_ATTR_OP_POLICY => Self::OpPolicy(
                Vec::<GenlCtrlOpPolicy>::parse(payload)
                    .context("failed to parse CTRL_ATTR_OP_POLICY")?,
            ),
            CTRL_ATTR_OP => Self::Op(parse_u32(payload)?),
            _ => Self::Unknown(DefaultNla::parse(buf)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctrl::mcast::GenlCtrlMcastGroup;
    use crate::ctrl::oppolicy::GenlCtrlOpPolicyIndex;
    use crate::ctrl::ops::GenlCtrlOp;
    use crate::ctrl::policy::{
        GenlCtrlPolicy, GenlCtrlPolicyEntry, GenlCtrlPolicyType,
    };

    // These tests compare against hard-coded little-endian wire bytes.
    #[cfg(target_endian = "little")]
    #[test]
    fn mcast_groups_parse() {
        let mcast_bytes: [u8; 24] = [
            24, 0, // Netlink header length
            7, 0, // Netlink header kind (Mcast groups)
            20, 0, // Mcast group nested NLA length
            1, 0, // Mcast group kind
            8, 0, // Id length
            2, 0, // Id kind
            1, 0, 0, 0, // Id
            8, 0, // Name length
            1, 0, // Name kind
            b't', b'e', b's', b't', // Name
        ];
        let nla_buffer = NlaBuffer::new(&mcast_bytes[..])
            .expect("Failed to create NlaBuffer");
        let result_attr = GenlCtrlAttr::parse(&nla_buffer)
            .expect("Failed to parse encoded McastGroups");
        let expected_attr =
            GenlCtrlAttr::McastGroups(vec![GenlCtrlMcastGroupSet::new(
                1,
                vec![
                    GenlCtrlMcastGroup::Id(1),
                    GenlCtrlMcastGroup::Name("test".to_string()),
                ],
            )]);
        assert_eq!(expected_attr, result_attr);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn mcast_groups_emit() {
        let mcast_attr = GenlCtrlAttr::McastGroups(vec![
            GenlCtrlMcastGroupSet::new(
                1,
                vec![
                    GenlCtrlMcastGroup::Id(7),
                    GenlCtrlMcastGroup::Name("group1".to_string()),
                ],
            ),
            GenlCtrlMcastGroupSet::new(
                2,
                vec![
                    GenlCtrlMcastGroup::Id(8),
                    GenlCtrlMcastGroup::Name("group2".to_string()),
                ],
            ),
        ]);
        let expected_bytes: [u8; 52] = [
            52, 0, // Netlink header length
            7, 0, // Netlink header kind (Mcast groups)
            24, 0, // Mcast group nested NLA length
            1, 0, // Mcast group kind (index 1)
            8, 0, // Id length
            2, 0, // Id kind
            7, 0, 0, 0, // Id
            11, 0, // Name length
            1, 0, // Name kind
            b'g', b'r', b'o', b'u', b'p', b'1', 0, // Name
            0, // mcast group padding
            24, 0, // Mcast group nested NLA length
            2, 0, // Mcast group kind (index 2)
            8, 0, // Id length
            2, 0, // Id kind
            8, 0, 0, 0, // Id
            11, 0, // Name length
            1, 0, // Name kind
            b'g', b'r', b'o', b'u', b'p', b'2', 0, // Name
            0, // padding
        ];
        let mut buf = Vec::new();
        mcast_attr.emit(&mut buf).unwrap();

        assert_eq!(&expected_bytes[..], &buf[..]);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn ops_parse() {
        let ops_bytes: [u8; 24] = [
            24, 0, // Netlink header length
            6, 0, // Netlink header kind (Ops)
            20, 0, // Op nested NLA length
            0, 0, // Op kind
            8, 0, // Id length
            1, 0, // Id kind
            1, 0, 0, 0, // Id
            8, 0, // Flags length
            2, 0, // Flags kind
            123, 0, 0, 0, // Flags
        ];
        let nla_buffer =
            NlaBuffer::new(&ops_bytes[..]).expect("Failed to create NlaBuffer");
        let result_attr = GenlCtrlAttr::parse(&nla_buffer)
            .expect("Failed to parse encoded McastGroups");
        let expected_attr = GenlCtrlAttr::Ops(vec![GenlCtrlOpSet::new(
            0,
            vec![GenlCtrlOp::Id(1), GenlCtrlOp::Flags(123)],
        )]);
        assert_eq!(expected_attr, result_attr);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn ops_emit() {
        let ops = GenlCtrlAttr::Ops(vec![
            GenlCtrlOpSet::new(
                1,
                vec![GenlCtrlOp::Id(1), GenlCtrlOp::Flags(11)],
            ),
            GenlCtrlOpSet::new(
                2,
                vec![GenlCtrlOp::Id(3), GenlCtrlOp::Flags(33)],
            ),
        ]);
        let expected_bytes: [u8; 44] = [
            44, 0, // Netlink header length
            6, 0, // Netlink header kind (Ops)
            20, 0, // Op nested NLA length
            1, 0, // Op kind
            8, 0, // Id length
            1, 0, // Id kind
            1, 0, 0, 0, // Id
            8, 0, // Flags length
            2, 0, // Flags kind
            11, 0, 0, 0, // Flags
            20, 0, // Op nested NLA length
            2, 0, // Op kind
            8, 0, // Id length
            1, 0, // Id kind
            3, 0, 0, 0, // Id
            8, 0, // Flags length
            2, 0, // Flags kind
            33, 0, 0, 0, // Flags
        ];
        let mut buf = Vec::new();
        ops.emit(&mut buf).unwrap();

        assert_eq!(&expected_bytes[..], &buf[..]);
    }

    #[test]
    fn policy_round_trip() {
        let policy = GenlCtrlAttr::Policy(vec![GenlCtrlPolicySet {
            index: 1,
            attrs: vec![GenlCtrlPolicyEntry {
                index: 1,
                attrs: vec![GenlCtrlPolicy::Type(GenlCtrlPolicyType::U32)],
            }],
        }]);

        let mut buf = Vec::new();
        policy.emit(&mut buf).unwrap();

        let nla_buffer = NlaBuffer::new(&buf).unwrap();
        assert_eq!(policy, GenlCtrlAttr::parse(&nla_buffer).unwrap());
    }

    #[test]
    fn op_policy_round_trip() {
        let policy = GenlCtrlAttr::OpPolicy(vec![GenlCtrlOpPolicy {
            cmd: 1,
            policy_idx: vec![
                GenlCtrlOpPolicyIndex::Do(2),
                GenlCtrlOpPolicyIndex::Dump(3),
            ],
        }]);

        let mut buf = Vec::new();
        policy.emit(&mut buf).unwrap();

        let nla_buffer = NlaBuffer::new(&buf).unwrap();
        assert_eq!(policy, GenlCtrlAttr::parse(&nla_buffer).unwrap());
    }

    #[test]
    fn ctrl_attr_nesting_matches_kernel() {
        let policy = GenlCtrlAttr::Policy(vec![GenlCtrlPolicySet {
            index: 0,
            attrs: vec![GenlCtrlPolicyEntry {
                index: 1,
                attrs: vec![],
            }],
        }]);
        let op_policy = GenlCtrlAttr::OpPolicy(vec![GenlCtrlOpPolicy {
            cmd: 1,
            policy_idx: vec![],
        }]);

        assert!(Nla::is_nested(&policy));
        assert!(Nla::is_nested(&op_policy));
        assert!(!Nla::is_nested(&GenlCtrlAttr::Ops(vec![])));
        assert!(!Nla::is_nested(&GenlCtrlAttr::McastGroups(vec![])));
    }
}

#[cfg(test)]
mod string_validation_tests {
    use super::*;
    use crate::ctrl::mcast::GenlCtrlMcastGroup;

    fn max_name_len() -> usize {
        // GENL_NAMSIZ includes the trailing NUL.
        GENL_NAMSIZ - 1
    }

    #[test]
    fn family_name_rejects_interior_nul() {
        let mut buf = Vec::new();
        let err = GenlCtrlAttr::FamilyName("foo\0bar".to_string())
            .emit(&mut buf)
            .unwrap_err();
        assert_eq!(err.kind(), EncodeErrorKind::InvalidValue);
        assert!(buf.is_empty());
    }

    #[test]
    fn family_name_accepts_maximum_length() {
        let name = "a".repeat(max_name_len());
        let attr = GenlCtrlAttr::FamilyName(name.clone());
        let mut buf = Vec::new();
        attr.emit(&mut buf).unwrap();

        let parsed = GenlCtrlAttr::parse(&NlaBuffer::new(&buf).unwrap())
            .expect("failed to parse maximum-length family name");
        assert_eq!(parsed, GenlCtrlAttr::FamilyName(name));
    }

    #[test]
    fn family_name_rejects_over_length() {
        let mut buf = Vec::new();
        let err = GenlCtrlAttr::FamilyName("a".repeat(max_name_len() + 1))
            .emit(&mut buf)
            .unwrap_err();
        assert!(err.is_too_large());
        assert!(buf.is_empty());
    }

    #[test]
    fn family_name_round_trip() {
        let attr = GenlCtrlAttr::FamilyName("nl80211".to_string());
        let mut buf = Vec::new();
        attr.emit(&mut buf).unwrap();

        let parsed = GenlCtrlAttr::parse(&NlaBuffer::new(&buf).unwrap())
            .expect("failed to parse family name");
        assert_eq!(parsed, attr);
    }

    #[test]
    fn mcast_name_rejects_interior_nul() {
        let mut buf = Vec::new();
        let err = GenlCtrlMcastGroup::Name("foo\0bar".to_string())
            .emit(&mut buf)
            .unwrap_err();
        assert_eq!(err.kind(), EncodeErrorKind::InvalidValue);
        assert!(buf.is_empty());
    }

    #[test]
    fn mcast_name_accepts_maximum_length() {
        let name = "a".repeat(max_name_len());
        let attr = GenlCtrlMcastGroup::Name(name.clone());
        let mut buf = Vec::new();
        attr.emit(&mut buf).unwrap();

        let parsed = GenlCtrlMcastGroup::parse(&NlaBuffer::new(&buf).unwrap())
            .expect("failed to parse maximum-length mcast name");
        assert_eq!(parsed, GenlCtrlMcastGroup::Name(name));
    }

    #[test]
    fn mcast_name_rejects_over_length() {
        let mut buf = Vec::new();
        let err = GenlCtrlMcastGroup::Name("a".repeat(max_name_len() + 1))
            .emit(&mut buf)
            .unwrap_err();
        assert!(err.is_too_large());
        assert!(buf.is_empty());
    }

    #[test]
    fn mcast_name_round_trip() {
        let attr = GenlCtrlMcastGroup::Name("scan".to_string());
        let mut buf = Vec::new();
        attr.emit(&mut buf).unwrap();

        let parsed = GenlCtrlMcastGroup::parse(&NlaBuffer::new(&buf).unwrap())
            .expect("failed to parse mcast name");
        assert_eq!(parsed, attr);
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::ctrl::policy::{
        GenlCtrlPolicy, GenlCtrlPolicyEntry, GenlCtrlPolicyType,
    };

    fn round_trip(policy: GenlCtrlAttr) -> GenlCtrlAttr {
        let mut buf = Vec::new();
        policy.emit(&mut buf).unwrap();
        GenlCtrlAttr::parse(&NlaBuffer::new(&buf).unwrap()).unwrap()
    }

    #[test]
    fn unsigned_min_max_round_trip() {
        let policy = GenlCtrlAttr::Policy(vec![GenlCtrlPolicySet {
            index: 2,
            attrs: vec![GenlCtrlPolicyEntry {
                index: 2,
                attrs: vec![
                    GenlCtrlPolicy::MinValueUnsigned(1),
                    GenlCtrlPolicy::MaxValueUnsigned(u64::MAX),
                ],
            }],
        }]);

        assert_eq!(round_trip(policy.clone()), policy);
    }

    #[test]
    fn byte_order_round_trip() {
        let policy = GenlCtrlAttr::Policy(vec![GenlCtrlPolicySet {
            index: 3,
            attrs: vec![GenlCtrlPolicyEntry {
                index: 3,
                attrs: vec![
                    GenlCtrlPolicy::Type(GenlCtrlPolicyType::U64),
                    GenlCtrlPolicy::ByteOrder(1),
                    GenlCtrlPolicy::MaxValueUnsigned(42),
                ],
            }],
        }]);

        assert_eq!(round_trip(policy.clone()), policy);
    }

    #[test]
    fn byte_order_uses_u32_wire_value() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&8u16.to_ne_bytes());
        bytes.extend_from_slice(
            &GenlCtrlPolicy::ByteOrder(1).kind().to_ne_bytes(),
        );
        bytes.extend_from_slice(&1u32.to_ne_bytes());

        let parsed = GenlCtrlPolicy::parse(&NlaBuffer::new(&bytes).unwrap())
            .expect("kernel emits NL_POLICY_TYPE_ATTR_BYTE_ORDER as u32");
        assert_eq!(parsed, GenlCtrlPolicy::ByteOrder(1));

        let mut emitted = Vec::new();
        parsed.emit(&mut emitted).unwrap();
        assert_eq!(emitted, bytes);
    }

    #[test]
    fn newer_nla_types_round_trip() {
        let policy = GenlCtrlAttr::Policy(vec![GenlCtrlPolicySet {
            index: 4,
            attrs: vec![GenlCtrlPolicyEntry {
                index: 4,
                attrs: vec![
                    GenlCtrlPolicy::Type(GenlCtrlPolicyType::Invalid),
                    GenlCtrlPolicy::Type(GenlCtrlPolicyType::SInt),
                    GenlCtrlPolicy::Type(GenlCtrlPolicyType::UInt),
                ],
            }],
        }]);

        assert_eq!(round_trip(policy.clone()), policy);
    }

    #[test]
    fn newer_nla_types_map_to_kernel_values() {
        for (nla_type, value) in [
            (GenlCtrlPolicyType::Invalid, 0u32),
            (GenlCtrlPolicyType::SInt, 16),
            (GenlCtrlPolicyType::UInt, 17),
            (GenlCtrlPolicyType::Unknown(42), 42),
        ] {
            assert_eq!(u32::from(nla_type), value);
            assert_eq!(GenlCtrlPolicyType::try_from(value).unwrap(), nla_type);
        }
    }

    #[test]
    fn unknown_nla_type_round_trip() {
        let policy = GenlCtrlAttr::Policy(vec![GenlCtrlPolicySet {
            index: 6,
            attrs: vec![GenlCtrlPolicyEntry {
                index: 6,
                attrs: vec![GenlCtrlPolicy::Type(GenlCtrlPolicyType::Unknown(
                    42,
                ))],
            }],
        }]);

        assert_eq!(round_trip(policy.clone()), policy);
    }

    #[test]
    fn unknown_policy_attr_round_trip() {
        let policy = GenlCtrlAttr::Policy(vec![GenlCtrlPolicySet {
            index: 5,
            attrs: vec![GenlCtrlPolicyEntry {
                index: 5,
                attrs: vec![GenlCtrlPolicy::Unknown(DefaultNla::new(
                    200,
                    vec![1, 2, 3, 4],
                ))],
            }],
        }]);

        assert_eq!(round_trip(policy.clone()), policy);
    }
}

#[cfg(test)]
mod unknown_attr_tests {
    use super::*;
    use crate::ctrl::mcast::GenlCtrlMcastGroup;
    use crate::ctrl::oppolicy::GenlCtrlOpPolicyIndex;
    use crate::ctrl::ops::GenlCtrlOp;

    #[test]
    fn unknown_ctrl_attr_round_trip() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&8u16.to_ne_bytes());
        bytes.extend_from_slice(&4242u16.to_ne_bytes());
        bytes.extend_from_slice(&[1, 2, 3, 4]);

        let parsed =
            GenlCtrlAttr::parse(&NlaBuffer::new(&bytes).unwrap()).unwrap();
        assert_eq!(
            parsed,
            GenlCtrlAttr::Unknown(DefaultNla::new(4242, vec![1, 2, 3, 4]))
        );

        let mut emitted = Vec::new();
        parsed.emit(&mut emitted).unwrap();
        assert_eq!(emitted, bytes);
    }

    fn single_nla(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes
    }

    #[test]
    fn unknown_nested_ctrl_attrs_round_trip() {
        let bytes = single_nla(4242, &[1, 2, 3, 4]);
        let buffer = NlaBuffer::new(&bytes).unwrap();
        let expected = DefaultNla::new(4242, vec![1, 2, 3, 4]);

        let mcast = GenlCtrlMcastGroup::parse(&buffer).unwrap();
        assert_eq!(mcast, GenlCtrlMcastGroup::Unknown(expected.clone()));
        let mut emitted = Vec::new();
        mcast.emit(&mut emitted).unwrap();
        assert_eq!(emitted, bytes);

        let op = GenlCtrlOp::parse(&buffer).unwrap();
        assert_eq!(op, GenlCtrlOp::Unknown(expected.clone()));
        let mut emitted = Vec::new();
        op.emit(&mut emitted).unwrap();
        assert_eq!(emitted, bytes);

        let op_policy = GenlCtrlOpPolicyIndex::parse(&buffer).unwrap();
        assert_eq!(op_policy, GenlCtrlOpPolicyIndex::Unknown(expected));
        let mut emitted = Vec::new();
        op_policy.emit(&mut emitted).unwrap();
        assert_eq!(emitted, bytes);
    }
}
