// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    Emitable, NetlinkMessage, NetlinkPayload, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    GenlCtrl, GenlCtrlAttrs, GenlCtrlCmd, GenlMessage,
};
use netlink_sys::{Socket, SocketAddr};

const NETLINK_GENERIC: isize = 16;

#[cfg(not(target_arch = "s390x"))]
#[test]
fn query_family_id() {
    let socket = Socket::new(NETLINK_GENERIC).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let mut genlmsg = GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName("nlctrl".to_owned())],
    });
    genlmsg.finalize();
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST;

    let mut txbuf = Vec::new();
    nlmsg.emit(&mut txbuf).unwrap();
    println!("Buffer length: {}", txbuf.len());

    socket.send(&txbuf, 0).unwrap();

    let (rxbuf, _addr) = socket.recv_from_full().unwrap();
    let rx_packet =
        <NetlinkMessage<GenlMessage<GenlCtrl>>>::deserialize(&rxbuf).unwrap();

    if let NetlinkPayload::InnerMessage(genlmsg) = rx_packet.payload {
        if GenlCtrlCmd::NewFamily == genlmsg.payload.cmd {
            let family_id = genlmsg
                .payload
                .nlas
                .iter()
                .find_map(|nla| {
                    if let GenlCtrlAttrs::FamilyId(id) = nla {
                        Some(*id)
                    } else {
                        None
                    }
                })
                .expect("Cannot find FamilyId attribute");
            // nlctrl's family must be 0x10
            assert_eq!(0x10, family_id);
        } else {
            panic!("Invalid payload type: {:?}", genlmsg.payload.cmd);
        }
    } else {
        panic!("Failed to get family ID");
    }
}
