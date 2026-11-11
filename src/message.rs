// SPDX-License-Identifier: MIT

//! Message definition and method implementations

use crate::header::{GenlHeader, GENL_HDRLEN};
use crate::traits::*;
use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, NetlinkDeserializable, NetlinkHeader,
    NetlinkMessagePayload, NetlinkPayload, ParseableParametrized,
};
use std::fmt::Debug;

#[cfg(doc)]
use netlink_packet_core::NetlinkMessage;

/// Represent the generic netlink messages
///
/// This type can wrap data types `F` which represents a generic family payload.
/// The message can be serialize/deserialize if the type `F` implements
/// [`GenlFamily`], [`Emitable`], and [`ParseableParametrized<[u8],
/// GenlHeader>`](ParseableParametrized).
///
/// # Equality
///
/// The derived `PartialEq` and `Eq` implementations compare every field,
/// including the resolved family ID. Two messages that differ only in their
/// resolved family ID are therefore not equal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenlMessage<F> {
    pub header: GenlHeader,
    pub payload: F,
    resolved_family_id: u16,
}

impl<F> GenlMessage<F> {
    /// Construct the message
    pub fn new(header: GenlHeader, payload: F, family_id: u16) -> Self {
        Self {
            header,
            payload,
            resolved_family_id: family_id,
        }
    }

    /// Construct the message by the given header and payload
    pub fn from_parts(header: GenlHeader, payload: F) -> Self {
        Self {
            header,
            payload,
            resolved_family_id: 0,
        }
    }

    /// Consume this message and return its header and payload
    pub fn into_parts(self) -> (GenlHeader, F) {
        (self.header, self.payload)
    }

    /// Return the previously set resolved family ID in this message.
    ///
    /// This value would be used to serialize the message only if
    /// the ([`GenlFamily::family_id()`]) return 0 in the underlying type.
    pub fn resolved_family_id(&self) -> u16 {
        self.resolved_family_id
    }

    /// Set the resolved dynamic family ID of the message, if the generic family
    /// uses dynamic generated ID by kernel.
    ///
    /// This method is a interface to provide other high level library to
    /// set the resolved family ID before the message is serialized.
    ///
    /// # Usage
    /// Normally, you don't have to call this function directly if you are
    /// using library which helps you handle the dynamic family id.
    ///
    /// If you are the developer of some high level generic netlink library,
    /// you can call this method to set the family id resolved by your resolver.
    /// Without having to modify the `message_type` field of the serialized
    /// netlink packet header before sending it.
    pub fn set_resolved_family_id(&mut self, family_id: u16) {
        self.resolved_family_id = family_id;
    }
}

impl<F> GenlMessage<F>
where
    F: GenlFamily,
{
    /// Build the message from the payload
    ///
    /// This function would automatically fill the header for you. You can
    /// directly emit the message without having to call
    /// [`finalize()`](Self::finalize).
    pub fn from_payload(payload: F) -> Self {
        Self {
            header: GenlHeader {
                cmd: payload.command(),
                version: payload.version(),
            },
            payload,
            resolved_family_id: 0,
        }
    }

    /// Ensure the header ([`GenlHeader`]) is consistent with the payload (`F:
    /// GenlFamily`):
    ///
    /// - Fill the command and version number into the header
    ///
    /// If you are not 100% sure the header is correct, this method should be
    /// called before calling [`Emitable::emit()`], as it could get error
    /// result if the header is inconsistent with the message.
    pub fn finalize(&mut self) {
        self.header.cmd = self.payload.command();
        self.header.version = self.payload.version();
    }

    /// Return the resolved family ID which should be filled into the
    /// `message_type` field in [`NetlinkHeader`].
    ///
    /// The implementation of [`NetlinkMessagePayload::message_type()`] uses
    /// this function's result as its return value. [`NetlinkMessage`] therefore
    /// fills the family ID into the `message_type` field when the message is
    /// emitted via [`Emitable`].
    pub fn family_id(&self) -> u16 {
        let static_id = self.payload.family_id();
        if static_id == 0 {
            self.resolved_family_id
        } else {
            static_id
        }
    }
}

impl<F> Emitable for GenlMessage<F>
where
    F: GenlFamily + Emitable + Debug,
{
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.header.emit(out)?;
        self.payload.emit(out)
    }
}

impl<F> NetlinkMessagePayload for GenlMessage<F>
where
    F: GenlFamily + Emitable + Debug,
{
    fn message_type(&self) -> u16 {
        self.family_id()
    }
}

impl<F> NetlinkDeserializable for GenlMessage<F>
where
    F: ParseableParametrized<[u8], GenlHeader> + Debug,
{
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, DecodeError> {
        GenlMessage::parse_with_param(payload, header.message_type)
    }
}

impl<F> ParseableParametrized<[u8], u16> for GenlMessage<F>
where
    F: ParseableParametrized<[u8], GenlHeader> + Debug,
{
    fn parse_with_param(
        buf: &[u8],
        message_type: u16,
    ) -> Result<Self, DecodeError> {
        let header = GenlHeader::parse(buf)?;
        let payload_buf = &buf[GENL_HDRLEN..];
        Ok(GenlMessage::new(
            header,
            F::parse_with_param(payload_buf, header)?,
            message_type,
        ))
    }
}

impl<F> From<GenlMessage<F>> for NetlinkPayload<GenlMessage<F>>
where
    F: Debug,
{
    fn from(message: GenlMessage<F>) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{append_u32, parse_u32};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestPayload {
        cmd: u8,
        version: u8,
        family_id: u16,
        value: u32,
    }

    impl GenlFamily for TestPayload {
        fn family_name() -> &'static str {
            "test"
        }

        fn family_id(&self) -> u16 {
            self.family_id
        }

        fn command(&self) -> u8 {
            self.cmd
        }

        fn version(&self) -> u8 {
            self.version
        }
    }

    impl Emitable for TestPayload {
        fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
            append_u32(out, self.value);
            Ok(())
        }
    }

    impl ParseableParametrized<[u8], GenlHeader> for TestPayload {
        fn parse_with_param(
            buf: &[u8],
            header: GenlHeader,
        ) -> Result<Self, DecodeError> {
            Ok(Self {
                cmd: header.cmd,
                version: header.version,
                // The dynamic family ID is carried by GenlMessage, not by the
                // family payload itself.
                family_id: 0,
                value: parse_u32(buf)?,
            })
        }
    }

    fn test_payload() -> TestPayload {
        TestPayload {
            cmd: 9,
            version: 1,
            family_id: 0,
            value: 0x1234,
        }
    }

    #[test]
    fn message_round_trip() {
        let message = GenlMessage::new(
            GenlHeader { cmd: 9, version: 1 },
            test_payload(),
            42,
        );

        let mut buf = Vec::new();
        message.emit(&mut buf).unwrap();

        let parsed =
            GenlMessage::<TestPayload>::parse_with_param(&buf, 42).unwrap();
        assert_eq!(parsed, message);
    }

    #[test]
    fn family_id_resolution() {
        let mut message = GenlMessage::new(
            GenlHeader { cmd: 9, version: 1 },
            test_payload(),
            42,
        );
        assert_eq!(message.family_id(), 42);
        assert_eq!(message.message_type(), 42);

        message.set_resolved_family_id(43);
        assert_eq!(message.resolved_family_id(), 43);
        assert_eq!(message.family_id(), 43);
        assert_eq!(message.message_type(), 43);
    }

    #[test]
    fn static_family_id_wins() {
        let payload = TestPayload {
            family_id: 7,
            ..test_payload()
        };
        let message =
            GenlMessage::new(GenlHeader { cmd: 0, version: 0 }, payload, 42);
        assert_eq!(message.family_id(), 7);
        assert_eq!(message.message_type(), 7);
    }

    #[test]
    fn from_payload_and_finalize_update_header() {
        let payload = TestPayload {
            cmd: 5,
            version: 2,
            ..test_payload()
        };
        let mut message = GenlMessage::from_payload(payload);
        assert_eq!(message.header, GenlHeader { cmd: 5, version: 2 });

        message.header = GenlHeader { cmd: 0, version: 0 };
        message.finalize();
        assert_eq!(message.header, GenlHeader { cmd: 5, version: 2 });
    }
}
