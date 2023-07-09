use super::{drive_req, nl_hdr_flags};
use anyhow::{Context, Result};
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_route::{
    constants::*, link::nlas::Nla as LinkNla, route::nlas::Nla as RouteNla, LinkMessage,
    RouteMessage, RtnlMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::{cmp::Reverse, collections::HashMap, net::IpAddr};

pub fn interface_names(socket: &Socket) -> Result<HashMap<u32, String>> {
    let mut packet = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::from(RtnlMessage::GetLink(LinkMessage::default())),
    );
    packet.header.flags = NLM_F_DUMP | NLM_F_REQUEST;
    packet.header.sequence_number = 1;

    let mut map = HashMap::new();
    drive_req(packet, socket, |inner| {
        if let RtnlMessage::NewLink(nl) = inner {
            if let Some(name) = nl.nlas.into_iter().find_map(|s| match s {
                LinkNla::IfName(n) => Some(n),
                _ => None,
            }) {
                map.insert(nl.header.index, name);
            }
        }
    })
    .context("Get interface names")?;

    Ok(map)
}

pub fn socket() -> Result<Socket> {
    let mut socket = Socket::new(NETLINK_ROUTE).context("Construct netlink route socket")?;
    socket.bind_auto().context("Bind netlink route socket")?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .context("Connect netlink route socket")?;
    Ok(socket)
}

#[derive(Clone, Debug)]
pub struct Prefix {
    pub dst: IpAddr,
    pub bits: u8,
}

impl Prefix {
    pub fn matches(&self, addr: IpAddr) -> bool {
        match (self.dst, addr) {
            (IpAddr::V4(route_dst), IpAddr::V4(addr)) => {
                u32::from_be_bytes(route_dst.octets()) >> (32 - self.bits)
                    == u32::from_be_bytes(addr.octets()) >> (32 - self.bits)
            }
            (IpAddr::V6(route_dst), IpAddr::V6(addr)) => {
                u128::from_be_bytes(route_dst.octets()) >> (128 - self.bits)
                    == u128::from_be_bytes(addr.octets()) >> (128 - self.bits)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}/{}", self.dst, self.bits))
    }
}

impl std::str::FromStr for Prefix {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut s = s.splitn(2, '/');
        let dst = s
            .next()
            .expect("Split iterator should return at least one element")
            .parse()
            .map_err(|_| ())?;
        let bits = match s.next() {
            Some(bits) => bits.parse().map_err(|_| ())?,
            None => match dst {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        };
        Ok(Prefix { dst, bits })
    }
}

struct Route {
    pfx: Prefix,
    iface: u32,
}

#[derive(Default)]
pub struct Rtbl(Vec<Route>);

// Dirty longest prefix implementation based on sorting, without even splitting v4/v6 (and just checking in order)
impl Rtbl {
    fn new(mut routes: Vec<Route>) -> Rtbl {
        routes.sort_by_key(|r| Reverse(r.pfx.bits)); // Normally, you'd also sort by metric, but
        Self(routes)
    }
    pub fn route(&self, addr: IpAddr) -> Option<u32> {
        for route in &self.0 {
            if route.pfx.matches(addr) {
                return Some(route.iface);
            }
        }
        None
    }
    pub fn for_iface(&self, iface: u32) -> impl Iterator<Item = Prefix> + '_ {
        self.0
            .iter()
            .filter(move |r| r.iface == iface)
            .map(|r| r.pfx.clone())
    }
}

pub fn local_routes(socket: &Socket) -> Result<Rtbl> {
    let mut route_message = RouteMessage::default();
    route_message.header.table = RT_TABLE_LOCAL; // This is respected
    route_message.header.kind = RTN_LOCAL; // This is not respected
    let packet = NetlinkMessage::new(
        nl_hdr_flags(NLM_F_REQUEST | NLM_F_DUMP),
        NetlinkPayload::from(RtnlMessage::GetRoute(route_message)),
    );

    let mut ret = Vec::new();
    drive_req(packet, socket, |inner| {
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
                        iface,
                        pfx: Prefix {
                            bits: route.header.destination_prefix_length,
                            dst: match route.header.address_family as u16 {
                                AF_INET => <[u8; 4]>::try_from(&dst[..])
                                    .expect("4 byte ipv4 addr?")
                                    .into(),
                                AF_INET6 => <[u8; 16]>::try_from(&dst[..])
                                    .expect("16 byte ipv6 addr?")
                                    .into(),
                                _ => unreachable!(
                                    "Unknown address family. Have nanites caused IPv8?"
                                ),
                            },
                        },
                    });
                }
            }
        }
    })
    .context("Read routing table")?;

    Ok(Rtbl::new(ret))
}
