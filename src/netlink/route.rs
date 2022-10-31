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
    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];

    assert!(buf.len() == packet.buffer_len());
    packet.serialize(&mut buf[..]);

    socket.send(&buf[..], 0).unwrap();

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;

    let mut map = HashMap::new();

    loop {
        let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();

        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet: NetlinkMessage<RtnlMessage> =
                NetlinkMessage::deserialize(bytes).unwrap();

            if let NetlinkPayload::InnerMessage(RtnlMessage::NewLink(nl)) = rx_packet.payload {
                if let Some(name) = nl.nlas.into_iter().find_map(|s| match s {
                    Nla::IfName(n) => Some(n),
                    _ => None,
                }) {
                    map.insert(nl.header.index, name);
                }
            } else if rx_packet.payload == NetlinkPayload::Done {
                return Ok(map);
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
}
