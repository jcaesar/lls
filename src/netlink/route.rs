use super::{drive_req, nl_hdr_flags};
use anyhow::{Context, Result};
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_route::{
    link::{InfoData, InfoKind, InfoVxlan, LinkAttribute, LinkExtentMask, LinkInfo, LinkMessage},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteType},
    RouteNetlinkMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::{cmp::Reverse, collections::HashMap, net::IpAddr};

#[derive(Default)]
pub struct Interfaces {
    pub id2name: HashMap<u32, String>,
    pub wireguard_ids: Vec<u32>,
    pub vxlan_ports: Vec<(u32, u16)>,
}

pub fn interface_names(socket: &Socket) -> Result<Interfaces> {
    let mut get_link = LinkMessage::default();
    get_link
        .attributes
        .push(LinkAttribute::ExtMask(vec![LinkExtentMask::SkipStats]));
    // get_link.header.interface_family = AddressFamily::Bridge;
    let mut packet = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::from(RouteNetlinkMessage::GetLink(get_link)),
    );
    packet.header.flags = NLM_F_DUMP | NLM_F_REQUEST;
    packet.header.sequence_number = 1;

    let mut map = HashMap::new();
    let mut wg_ids = Vec::new();
    let mut vxlan_ports = Vec::new();
    drive_req(packet, socket, |inner| {
        if let RouteNetlinkMessage::NewLink(nl) = inner {
            for nla in nl.attributes {
                match nla {
                    LinkAttribute::IfName(name) => {
                        map.insert(nl.header.index, name);
                    }
                    LinkAttribute::LinkInfo(infos) => {
                        for info in infos {
                            match info {
                                LinkInfo::Kind(InfoKind::Wireguard) => {
                                    wg_ids.push(nl.header.index);
                                }
                                LinkInfo::Data(InfoData::Vxlan(data)) => {
                                    for datum in data {
                                        if let InfoVxlan::Port(port) = datum {
                                            vxlan_ports.push((nl.header.index, port));
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                    _ => (),
                }
            }
        }
    })
    .context("Get interface names")?;

    Ok(Interfaces {
        id2name: map,
        wireguard_ids: wg_ids,
        vxlan_ports,
    })
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
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut s = s.splitn(2, '/');
        let dst = s
            .next()
            .expect("Split iterator should return at least one element")
            .parse()
            .context("Parse IP address")?;
        let bits = match s.next() {
            Some(bits) => bits.parse().context("Parse mask")?,
            None => match dst {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        };
        Ok(Prefix { dst, bits })
    }
}

#[derive(Debug)]
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
    const RT_TABLE_LOCAL: u8 = 0;
    let mut route_message = RouteMessage::default();
    route_message.header.table = RT_TABLE_LOCAL; // This is respected
    route_message.header.kind = RouteType::Local; // This is not respected
    let packet = NetlinkMessage::new(
        nl_hdr_flags(NLM_F_REQUEST | NLM_F_DUMP),
        NetlinkPayload::from(RouteNetlinkMessage::GetRoute(route_message)),
    );

    let mut ret = Vec::new();
    drive_req(packet, socket, |inner| {
        if let RouteNetlinkMessage::NewRoute(route) = inner {
            if route.header.kind == RouteType::Local {
                let iface = route.attributes.iter().find_map(|nla| match nla {
                    RouteAttribute::Oif(ifc) => Some(ifc),
                    _ => None,
                });
                let dst = route.attributes.iter().find_map(|nla| match nla {
                    RouteAttribute::Destination(bits) => Some(bits),
                    _ => None,
                });
                if let (Some(&iface), Some(dst)) = (iface, dst) {
                    let dst = match *dst {
                        RouteAddress::Inet(a) => IpAddr::from(a),
                        RouteAddress::Inet6(a) => IpAddr::from(a),
                        _ => unreachable!("Unknown address family. Have nanites caused IPv8?"),
                    };
                    let bits = route.header.destination_prefix_length;
                    let pfx = Prefix { bits, dst };
                    ret.push(Route { iface, pfx });
                }
            }
        }
    })
    .context("Read routing table")?;

    Ok(Rtbl::new(ret))
}
