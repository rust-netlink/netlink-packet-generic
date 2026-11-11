// SPDX-License-Identifier: MIT

use crate::constants::*;
use netlink_packet_core::{
    append_bytes, append_u16, append_u32, parse_string, parse_u16, parse_u32,
    DecodeError, Emitable, EncodeError, EncodeErrorKind, ErrorContext, Nla,
    NlaBuffer, NlasIterator, Parseable,
};

mod mcast;
mod oppolicy;
mod ops;
mod policy;

pub use mcast::*;
pub use oppolicy::*;
pub use ops::*;
pub use policy::*;

/// Append a NUL-terminated netlink string.
///
/// Interior NUL bytes are rejected because they would make parsing stop
/// early and turn the emit/parse round trip lossy. The overall length is
/// bounded by [`Nla::emit`] through `nla_total_size`, which accounts for
/// the trailing terminator added here.
///
/// This matches the kernel requirements for generic-netlink names:
/// `Family::const_new` validates its name with `CStr::from_bytes_with_nul`
/// and rejects names too long for `genl_family::name`, while
/// `MulticastGroup::const_new` takes a `&CStr` and rejects names too long
/// for `genl_multicast_group::name` (see `rust/kernel/net/netlink.rs`).
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
    append_bytes(out, value.as_bytes());
    out.push(0);
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenlCtrlAttrs {
    FamilyId(u16),
    FamilyName(String),
    Version(u32),
    HdrSize(u32),
    MaxAttr(u32),
    Ops(Vec<Vec<OpAttrs>>),
    McastGroups(Vec<Vec<McastGrpAttrs>>),
    Policy(PolicyAttr),
    OpPolicy(OppolicyAttr),
    Op(u32),
}

impl Nla for GenlCtrlAttrs {
    fn kind(&self) -> u16 {
        use GenlCtrlAttrs::*;
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
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        use GenlCtrlAttrs::*;
        match self {
            FamilyId(v) => append_u16(out, *v),
            FamilyName(s) => append_nl_string(out, s)?,
            Version(v) => append_u32(out, *v),
            HdrSize(v) => append_u32(out, *v),
            MaxAttr(v) => append_u32(out, *v),
            Ops(nlas) => OpList::from(nlas).as_slice().emit(out)?,
            McastGroups(nlas) => {
                McastGroupList::from(nlas).as_slice().emit(out)?
            }
            Policy(nla) => nla.emit(out)?,
            OpPolicy(nla) => nla.emit(out)?,
            Op(v) => append_u32(out, *v),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for GenlCtrlAttrs {
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
                    .map(|nlas| {
                        nlas.nlas()?
                            .map(|nla| OpAttrs::parse(&nla))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .collect::<Result<Vec<Vec<_>>, _>>()
                    .context("failed to parse CTRL_ATTR_OPS")?;
                Self::Ops(ops)
            }
            CTRL_ATTR_MCAST_GROUPS => {
                let groups = NlasIterator::new(payload)?
                    .map(|nlas| {
                        nlas.nlas()?
                            .map(|nla| McastGrpAttrs::parse(&nla))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .collect::<Result<Vec<Vec<_>>, _>>()
                    .context("failed to parse CTRL_ATTR_MCAST_GROUPS")?;
                Self::McastGroups(groups)
            }
            CTRL_ATTR_POLICY => Self::Policy(
                PolicyAttr::parse(
                    &NlaBuffer::new(payload)
                        .context("failed to parse CTRL_ATTR_POLICY")?,
                )
                .context("failed to parse CTRL_ATTR_POLICY")?,
            ),
            CTRL_ATTR_OP_POLICY => Self::OpPolicy(
                OppolicyAttr::parse(
                    &NlaBuffer::new(payload)
                        .context("failed to parse CTRL_ATTR_OP_POLICY")?,
                )
                .context("failed to parse CTRL_ATTR_OP_POLICY")?,
            ),
            CTRL_ATTR_OP => Self::Op(parse_u32(payload)?),
            kind => {
                return Err(DecodeError::from(format!(
                    "Unknown NLA type: {kind}"
                )))
            }
        })
    }
}

#[cfg(target_endian = "little")]
#[cfg(test)]
mod tests {
    use super::*;

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
        let result_attr = GenlCtrlAttrs::parse(&nla_buffer)
            .expect("Failed to parse encoded McastGroups");
        let expected_attr = GenlCtrlAttrs::McastGroups(vec![vec![
            McastGrpAttrs::Id(1),
            McastGrpAttrs::Name("test".to_string()),
        ]]);
        assert_eq!(expected_attr, result_attr);
    }

    #[test]
    fn mcast_groups_emit() {
        let mcast_attr = GenlCtrlAttrs::McastGroups(vec![
            vec![
                McastGrpAttrs::Id(7),
                McastGrpAttrs::Name("group1".to_string()),
            ],
            vec![
                McastGrpAttrs::Id(8),
                McastGrpAttrs::Name("group2".to_string()),
            ],
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
        let result_attr = GenlCtrlAttrs::parse(&nla_buffer)
            .expect("Failed to parse encoded McastGroups");
        let expected_attr =
            GenlCtrlAttrs::Ops(vec![vec![OpAttrs::Id(1), OpAttrs::Flags(123)]]);
        assert_eq!(expected_attr, result_attr);
    }

    #[test]
    fn ops_emit() {
        let ops = GenlCtrlAttrs::Ops(vec![
            vec![OpAttrs::Id(1), OpAttrs::Flags(11)],
            vec![OpAttrs::Id(3), OpAttrs::Flags(33)],
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
        let policy = GenlCtrlAttrs::Policy(PolicyAttr {
            index: 1,
            attr_policy: AttributePolicyAttr {
                index: 1,
                policies: vec![NlPolicyTypeAttrs::Type(NlaType::U32)],
            },
        });

        let mut buf = Vec::new();
        policy.emit(&mut buf).unwrap();

        let nla_buffer = NlaBuffer::new(&buf).unwrap();
        assert_eq!(policy, GenlCtrlAttrs::parse(&nla_buffer).unwrap());
    }

    #[test]
    fn op_policy_round_trip() {
        let policy = GenlCtrlAttrs::OpPolicy(OppolicyAttr {
            cmd: 1,
            policy_idx: vec![
                OppolicyIndexAttr::Do(2),
                OppolicyIndexAttr::Dump(3),
            ],
        });

        let mut buf = Vec::new();
        policy.emit(&mut buf).unwrap();

        let nla_buffer = NlaBuffer::new(&buf).unwrap();
        assert_eq!(policy, GenlCtrlAttrs::parse(&nla_buffer).unwrap());
    }
}

#[cfg(test)]
mod string_validation_tests {
    use super::*;
    use netlink_packet_core::NLA_MAX_VALUE_LEN;

    fn max_name_len() -> usize {
        // The trailing NUL is part of the attribute value.
        NLA_MAX_VALUE_LEN - 1
    }

    #[test]
    fn family_name_rejects_interior_nul() {
        let mut buf = Vec::new();
        let err = GenlCtrlAttrs::FamilyName("foo\0bar".to_string())
            .emit(&mut buf)
            .unwrap_err();
        assert_eq!(err.kind(), EncodeErrorKind::InvalidValue);
        assert!(buf.is_empty());
    }

    #[test]
    fn family_name_accepts_maximum_length() {
        let name = "a".repeat(max_name_len());
        let attr = GenlCtrlAttrs::FamilyName(name.clone());
        let mut buf = Vec::new();
        attr.emit(&mut buf).unwrap();

        let parsed = GenlCtrlAttrs::parse(&NlaBuffer::new(&buf).unwrap())
            .expect("failed to parse maximum-length family name");
        assert_eq!(parsed, GenlCtrlAttrs::FamilyName(name));
    }

    #[test]
    fn family_name_rejects_over_length() {
        let mut buf = Vec::new();
        let err = GenlCtrlAttrs::FamilyName("a".repeat(max_name_len() + 1))
            .emit(&mut buf)
            .unwrap_err();
        assert!(err.is_too_large());
        assert!(buf.is_empty());
    }

    #[test]
    fn family_name_round_trip() {
        let attr = GenlCtrlAttrs::FamilyName("nl80211".to_string());
        let mut buf = Vec::new();
        attr.emit(&mut buf).unwrap();

        let parsed = GenlCtrlAttrs::parse(&NlaBuffer::new(&buf).unwrap())
            .expect("failed to parse family name");
        assert_eq!(parsed, attr);
    }

    #[test]
    fn mcast_name_rejects_interior_nul() {
        let mut buf = Vec::new();
        let err = McastGrpAttrs::Name("foo\0bar".to_string())
            .emit(&mut buf)
            .unwrap_err();
        assert_eq!(err.kind(), EncodeErrorKind::InvalidValue);
        assert!(buf.is_empty());
    }

    #[test]
    fn mcast_name_accepts_maximum_length() {
        let name = "a".repeat(max_name_len());
        let attr = McastGrpAttrs::Name(name.clone());
        let mut buf = Vec::new();
        attr.emit(&mut buf).unwrap();

        let parsed = McastGrpAttrs::parse(&NlaBuffer::new(&buf).unwrap())
            .expect("failed to parse maximum-length mcast name");
        assert_eq!(parsed, McastGrpAttrs::Name(name));
    }

    #[test]
    fn mcast_name_rejects_over_length() {
        let mut buf = Vec::new();
        let err = McastGrpAttrs::Name("a".repeat(max_name_len() + 1))
            .emit(&mut buf)
            .unwrap_err();
        assert!(err.is_too_large());
        assert!(buf.is_empty());
    }

    #[test]
    fn mcast_name_round_trip() {
        let attr = McastGrpAttrs::Name("scan".to_string());
        let mut buf = Vec::new();
        attr.emit(&mut buf).unwrap();

        let parsed = McastGrpAttrs::parse(&NlaBuffer::new(&buf).unwrap())
            .expect("failed to parse mcast name");
        assert_eq!(parsed, attr);
    }
}
