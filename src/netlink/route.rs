use super::drive_req;
use anyhow::Result;
use netlink_packet_route::{
    constants::*, link::nlas::Nla as LinkNla, route::nlas::Nla as RouteNla, LinkMessage,
    NetlinkHeader, NetlinkMessage, NetlinkPayload, RouteMessage, RtnlMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::{cmp::Reverse, collections::HashMap, net::IpAddr};

pub fn interface_names(socket: &Socket) -> Result<HashMap<u32, String>> {
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
                LinkNla::IfName(n) => Some(n),
                _ => None,
            }) {
                map.insert(nl.header.index, name);
            }
        }
    })?;

    Ok(map)
}

pub fn socket() -> Socket {
    let mut socket = Socket::new(NETLINK_ROUTE).unwrap();
    let _port_number = socket.bind_auto().unwrap().port_number();
    socket.connect(&SocketAddr::new(0, 0)).unwrap();
    socket
}

struct Route {
    dst: IpAddr,
    bits: u8,
    iface: u32,
}

pub struct Rtbl(Vec<Route>);

// Dirty longest prefix implementation based on sorting, without even splitting v4/v6 (and just checking in order)
impl Rtbl {
    pub fn empty() -> Self {
        Self(Vec::new())
    }
    fn new(mut routes: Vec<Route>) -> Rtbl {
        routes.sort_by_key(|r| Reverse(r.bits)); // Normally, you'd also sort by metric, but
        Self(routes)
    }
    pub fn route(&self, addr: IpAddr) -> Option<u32> {
        for route in &self.0 {
            let matches = match (route.dst, addr) {
                (IpAddr::V4(route_dst), IpAddr::V4(addr)) => {
                    u32::from_be_bytes(route_dst.octets()) >> (32 - route.bits)
                        == u32::from_be_bytes(addr.octets()) >> (32 - route.bits)
                }
                (IpAddr::V6(route_dst), IpAddr::V6(addr)) => {
                    u128::from_be_bytes(route_dst.octets()) >> (128 - route.bits)
                        == u128::from_be_bytes(addr.octets()) >> (128 - route.bits)
                }
                _ => false,
            };
            if matches {
                return Some(route.iface);
            }
        }
        None
    }
}

pub fn local_routes(socket: &Socket) -> Result<Rtbl> {
    let mut route_message = RouteMessage::default();
    route_message.header.table = RT_TABLE_LOCAL; // This is respected
    route_message.header.kind = RTN_LOCAL; // This is not respected
    let packet = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            ..Default::default()
        },
        payload: NetlinkPayload::from(RtnlMessage::GetRoute(route_message)),
    };

    let mut ret = Vec::new();
    drive_req(packet, &socket, |inner| {
        if let RtnlMessage::NewRoute(route) = inner {
            if route.header.table == RT_TABLE_LOCAL && route.header.kind == RTN_LOCAL {
                let iface = route.nlas.iter().find_map(|nla| match nla {
                    RouteNla::Oif(ifc) => Some(ifc),
                    _ => None,
                });
                let dst = route.nlas.iter().find_map(|nla| match nla {
                    RouteNla::Destination(bits) => Some(bits),
                    _ => None,
                });
                if let (Some(&iface), Some(dst)) = (iface, dst) {
                    // TODO: more anyhow, less expect/unreachable
                    ret.push(Route {
                        bits: route.header.destination_prefix_length,
                        iface,
                        dst: match route.header.address_family as u16 {
                            AF_INET => <[u8; 4]>::try_from(&dst[..])
                                .expect("4 byte ipv4 addr?")
                                .into(),
                            AF_INET6 => <[u8; 16]>::try_from(&dst[..])
                                .expect("16 byte ipv6 addr?")
                                .into(),
                            _ => unreachable!("Unknown address family. Have nanites caused IPv8?"),
                        },
                    });
                }
            }
        }
    })?;

    Ok(Rtbl::new(ret))
}
