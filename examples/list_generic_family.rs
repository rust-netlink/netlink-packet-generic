// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    Emitable, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    GenlCtrlAttr, GenlCtrlCmd, GenlCtrlMessage, GenlMessage,
};
use netlink_sys::{Socket, SocketAddr};

const NETLINK_GENERIC: isize = 16;

fn main() {
    let socket = Socket::new(NETLINK_GENERIC).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let mut genlmsg = GenlMessage::from_payload(GenlCtrlMessage::new(
        GenlCtrlCmd::GetFamily,
        vec![],
    ));
    genlmsg.finalize();
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut txbuf = Vec::new();
    nlmsg.emit(&mut txbuf).unwrap();

    socket.send(&txbuf, 0).unwrap();

    'outer: loop {
        let (rxbuf, _addr) = socket.recv_from_full().unwrap();
        let mut offset = 0;
        while offset < rxbuf.len() {
            let buf = &rxbuf[offset..];
            // Parse the message
            let msg =
                <NetlinkMessage<GenlMessage<GenlCtrlMessage>>>::deserialize(
                    buf,
                )
                .unwrap();

            match msg.payload {
                NetlinkPayload::Done(_) => break 'outer,
                NetlinkPayload::InnerMessage(genlmsg) => {
                    if GenlCtrlCmd::NewFamily == genlmsg.payload.cmd {
                        print_entry(genlmsg.payload.nlas);
                    }
                }
                NetlinkPayload::Error(err) => {
                    eprintln!("Received a netlink error message: {err:?}");
                    return;
                }
                _ => {}
            }

            offset += msg.header.length as usize;
        }
    }
}

fn print_entry(entry: Vec<GenlCtrlAttr>) {
    let family_id = entry
        .iter()
        .find_map(|nla| {
            if let GenlCtrlAttr::FamilyId(id) = nla {
                Some(*id)
            } else {
                None
            }
        })
        .expect("Cannot find FamilyId attribute");
    let family_name = entry
        .iter()
        .find_map(|nla| {
            if let GenlCtrlAttr::FamilyName(name) = nla {
                Some(name.as_str())
            } else {
                None
            }
        })
        .expect("Cannot find FamilyName attribute");
    let version = entry
        .iter()
        .find_map(|nla| {
            if let GenlCtrlAttr::Version(ver) = nla {
                Some(*ver)
            } else {
                None
            }
        })
        .expect("Cannot find Version attribute");
    let hdrsize = entry
        .iter()
        .find_map(|nla| {
            if let GenlCtrlAttr::HdrSize(hdr) = nla {
                Some(*hdr)
            } else {
                None
            }
        })
        .expect("Cannot find HdrSize attribute");

    if hdrsize == 0 {
        println!("0x{family_id:04x} {family_name} [Version {version}]");
    } else {
        println!("0x{family_id:04x} {family_name} [Version {version}] [Header {hdrsize} bytes]");
    }
}
