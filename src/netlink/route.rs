use super::drive_req;
use anyhow::Result;
use netlink_packet_route::{
    link::nlas::Nla, LinkMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload, RtnlMessage,
    NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::collections::HashMap;

pub fn interface_names() -> Result<HashMap<u32, String>> {
    let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();

    let mut packet = NetlinkMessage {
        header: NetlinkHeader::default(),
        payload: NetlinkPayload::from(RtnlMessage::GetLink(LinkMessage::default())),
    };
    packet.header.flags = NLM_F_DUMP | NLM_F_REQUEST;
    packet.header.sequence_number = 1;

    let mut map = HashMap::new();
    drive_req(packet, &socket, |inner| {
        if let RtnlMessage::NewLink(nl) = inner {
            if let Some(name) = nl.nlas.into_iter().find_map(|s| match s {
                Nla::IfName(n) => Some(n),
                _ => None,
            }) {
                map.insert(nl.header.index, name);
            }
        }
    })?;

    Ok(map)
}
