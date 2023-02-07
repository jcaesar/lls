use super::{drive_req, nl_hdr_flags, route::Rtbl};
use crate::Ino;
use anyhow::Result;
use netlink_packet_core::{NetlinkMessage, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_sock_diag::{
    constants::*,
    inet::{nlas::Nla, ExtensionFlags, InetRequest, InetResponse, SocketId, StateFlags},
    SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};
use std::{collections::HashMap, fmt::Display, net::IpAddr};

pub fn all_sockets(
    interfaces: &HashMap<u32, String>,
    local_routes: Rtbl,
) -> Result<HashMap<Ino, SockInfo>> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let mut ret = HashMap::new();

    let protocols = [
        Protocol::TCP,
        Protocol::UDP,
        Protocol::UDPlite,
        Protocol::RAW,
        Protocol::SCTP,
    ];
    let families = [Family::V4, Family::V6];

    for family in families {
        for protocol in protocols {
            let packet = NetlinkMessage::new(
                nl_hdr_flags(NLM_F_REQUEST | NLM_F_DUMP),
                SockDiagMessage::InetRequest(InetRequest {
                    family: family.proto_const(),
                    protocol: protocol.proto_const(),
                    socket_id: family.proto_socket_id(),
                    extensions: ExtensionFlags::empty(),
                    states: StateFlags::all(),
                })
                .into(),
            );
            drive_req(packet, &socket, |inner| match inner {
                SockDiagMessage::InetResponse(response) => {
                    if response.header.socket_id.destination_port == 0 {
                        ret.insert(
                            response.header.inode.into(),
                            SockInfo::new(family, protocol, *response, interfaces, &local_routes),
                        );
                    }
                }
                _ => unreachable!("We made an InetRequest, we get an InetResponse, yeah?"),
            })?;
        }
    }
    Ok(ret)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    V4,
    V6,
    Both,
}
impl Family {
    fn proto_const(&self) -> u8 {
        match self {
            Family::V4 => AF_INET,
            Family::V6 => AF_INET6,
            Family::Both => panic!("Gee..."),
        }
    }
    fn proto_socket_id(&self) -> SocketId {
        match self {
            Family::V4 => SocketId::new_v4(),
            Family::V6 => SocketId::new_v6(),
            Family::Both => panic!("Gee..."),
        }
    }
}
impl Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Family::V4 => f.write_str("v4"),
            Family::V6 => f.write_str("v6"),
            Family::Both => f.write_str("*"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(clippy::upper_case_acronyms)]
pub enum Protocol {
    TCP,
    UDP,
    UDPlite,
    RAW,
    SCTP,
}
impl Protocol {
    fn proto_const(&self) -> u8 {
        match self {
            Protocol::TCP => IPPROTO_TCP,
            Protocol::UDP => IPPROTO_UDP,
            Protocol::UDPlite => IPPROTO_UDPLITE,
            Protocol::RAW => IPPROTO_RAW,
            Protocol::SCTP => IPPROTO_SCTP,
        }
    }
}
impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::TCP => f.write_str("tcp"),
            Protocol::UDP => f.write_str("udp"),
            Protocol::UDPlite => f.write_str("udplite"),
            Protocol::RAW => f.write_str("raw"),
            Protocol::SCTP => f.write_str("sctp"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SockInfo<'a> {
    pub family: Family,
    pub protocol: Protocol,
    pub port: u16,
    pub addr: IpAddr,
    pub uid: u32,
    pub ino: Ino,
    pub iface: Option<&'a str>,
}
impl<'a> SockInfo<'a> {
    fn new(
        family: Family,
        protocol: Protocol,
        ir: InetResponse,
        interfaces: &'a HashMap<u32, String>,
        local_routes: &Rtbl,
    ) -> Self {
        let family = if ir
            .nlas
            .iter()
            .any(|nla| matches!(&nla, Nla::SkV6Only(false)))
        {
            Family::Both
        } else {
            family
        };
        let addr = ir.header.socket_id.source_address;
        let iface = interfaces
            .get(&ir.header.socket_id.interface_id)
            .or_else(|| {
                local_routes
                    .route(addr)
                    .and_then(|iface| interfaces.get(&iface))
            })
            .map(|x| &**x);
        Self {
            family,
            protocol,
            port: ir.header.socket_id.source_port,
            addr,
            uid: ir.header.uid,
            ino: ir.header.inode.into(),
            iface,
        }
    }
}
impl PartialOrd for SockInfo<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SockInfo<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let key = |s: &SockInfo| (s.port, s.protocol, s.addr, s.family);
        key(self).cmp(&key(other))
    }
}
