mod termtree;

use anyhow::Result;
use itertools::Itertools;
use netlink_packet_sock_diag::{
    constants::*,
    inet::{nlas::Nla, ExtensionFlags, InetRequest, InetResponse, SocketId, StateFlags},
    NetlinkHeader, NetlinkMessage, NetlinkPayload, SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};
use procfs::process::{all_processes, Process};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    io::{stdout, BufWriter, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
    path::PathBuf,
};
use users::{Users, UsersCache};

fn main() -> Result<()> {
    let users_cache = UsersCache::new();
    let mut socks = all_sockets()?;
    let mut output = termtree::Tree::new();

    let mut lps = all_processes()?
        .filter_map(|p| ProcDesc::inspect_ps(p, &mut socks, &users_cache).ok())
        .filter(|p| !p.sockets.is_empty())
        .collect::<Vec<_>>();
    lps.iter_mut().for_each(|p| p.sockets.sort());
    lps.sort();
    for pd in lps {
        output.node(
            format!(
                "{} / {} / {}",
                pd.pid,
                pd.user,
                pd.name.as_deref().unwrap_or("???")
            ),
            sockets_tree(&pd.sockets),
        );
    }
    let mut socks = socks
        .values()
        .into_group_map_by(|s| s.uid)
        .into_iter()
        .collect::<Vec<_>>();
    socks.iter_mut().for_each(|(_, x)| x.sort());
    socks.sort_by_cached_key(|t| t.1.clone());
    for (uid, socks) in socks {
        output.node(format!("??? / {uid} / ???",), sockets_tree(socks));
    }
    let stdout = &mut BufWriter::new(stdout());
    output.render(
        terminal_size::terminal_size().map(|(terminal_size::Width(w), _)| w.into()),
        &mut |s| stdout.write_all(s).expect("stdout shut"),
    );

    Ok(())
}

fn sockets_tree(
    sockets: impl IntoIterator<Item = impl Deref<Target = SockInfo>>,
) -> termtree::Tree {
    let mut pout = termtree::Tree::new();
    let mut groups = BTreeMap::<_, Vec<_>>::new();
    for s in sockets {
        groups.entry((s.port, s.protocol)).or_default().push(s);
    }
    for ((port, proto), socks) in groups {
        let mut sout = termtree::Tree::new();
        if socks.len() == 2
            && socks.iter().any(|s| s.addr == Ipv4Addr::UNSPECIFIED)
            && socks.iter().any(|s| s.addr == Ipv6Addr::UNSPECIFIED)
        {
            sout.leaf("0.0.0.0 + ::".into());
        } else {
            for sock in socks {
                match sock.family {
                    Family::Both => sout.leaf("*".into()),
                    _ => sout.leaf(format!("{}", sock.addr)),
                };
            }
        }
        pout.node(format!(":{port} {proto}"), sout);
    }
    pout
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Family {
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
enum Protocol {
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
struct SockInfo {
    family: Family,
    protocol: Protocol,
    port: u16,
    addr: IpAddr,
    uid: u32,
    ino: Ino,
}
impl SockInfo {
    fn new(family: Family, protocol: Protocol, ir: InetResponse) -> Self {
        let family = ir
            .nlas
            .iter()
            .find(|nla| matches!(nla, Nla::SkV6Only(false)))
            .is_some()
            .then_some(Family::Both)
            .unwrap_or(family);
        Self {
            family,
            protocol,
            port: ir.header.socket_id.source_port,
            addr: ir.header.socket_id.source_address,
            uid: ir.header.uid,
            ino: ir.header.inode.into(),
        }
    }
}
impl PartialOrd for SockInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SockInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let key = |s: &SockInfo| (s.port, s.protocol, s.addr, s.family);
        key(self).cmp(&key(other))
    }
}

fn all_sockets() -> Result<HashMap<Ino, SockInfo>> {
    let mut ret = HashMap::new();

    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
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
            let mut packet = NetlinkMessage {
                header: NetlinkHeader {
                    flags: NLM_F_REQUEST | NLM_F_DUMP,
                    ..Default::default()
                },
                payload: SockDiagMessage::InetRequest(InetRequest {
                    family: family.proto_const(),
                    protocol: protocol.proto_const(),
                    socket_id: family.proto_socket_id(),
                    extensions: ExtensionFlags::empty(),
                    states: StateFlags::all(),
                })
                .into(),
            };
            packet.finalize();
            let mut buf = vec![0; packet.header.length as usize];
            assert_eq!(buf.len(), packet.buffer_len());
            packet.serialize(&mut buf[..]);
            socket.send(&buf[..], 0)?;
            let mut receive_buffer = vec![0; 4096];
            let mut offset = 0;

            'recv: while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
                loop {
                    let bytes = &receive_buffer[offset..];
                    let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();

                    match rx_packet.payload {
                        NetlinkPayload::Noop | NetlinkPayload::Ack(_) => {}
                        NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                            if response.header.socket_id.destination_port == 0 {
                                ret.insert(
                                    response.header.inode.into(),
                                    SockInfo::new(family, protocol, *response),
                                );
                            }
                        }
                        NetlinkPayload::Done
                        | NetlinkPayload::Error(_)
                        | NetlinkPayload::Overrun(_)
                        | _ => break 'recv,
                    }

                    offset += rx_packet.header.length as usize;
                    if offset == size || rx_packet.header.length == 0 {
                        offset = 0;
                        break;
                    }
                }
            }
        }
    }
    Ok(ret)
}

type Ino = u64;
type Pid = i32;
#[derive(Debug, PartialEq, Eq)]
struct ProcDesc {
    pid: Pid,
    user: String,
    name: Option<String>,
    sockets: Vec<SockInfo>,
}

impl ProcDesc {
    fn inspect_ps(
        p: Result<Process, procfs::ProcError>,
        socks: &mut HashMap<Ino, SockInfo>,
        user_names: &UsersCache,
    ) -> Result<ProcDesc> {
        let p = p?;
        let name = ProcDesc::ps_name(&p);
        let user = match p.root().ok().filter(|p| p == &PathBuf::from("/")).is_some() {
            true => user_names
                .get_user_by_uid(p.uid()?)
                .map_or_else(String::new, |u| u.name().to_string_lossy().into_owned()),
            false => String::new(),
        };
        let sockets = p
            .fd()?
            .filter_map(|f| match f.ok()?.target {
                procfs::process::FDTarget::Socket(s) => socks.remove(&s),
                _ => None,
            })
            .collect();
        Ok(ProcDesc {
            pid: p.pid,
            name,
            sockets,
            user,
        })
    }

    fn ps_name(p: &Process) -> Option<String> {
        p.exe()
            .ok()
            // I considered checking whether to check if the exe file_name is on $PATH
            // and print the whole path if not. Nah.
            .and_then(|p| p.file_name().map(|p| p.to_string_lossy().into_owned()))
            .or(p.cmdline().ok().and_then(|v| v.into_iter().next()))
    }
}

impl PartialOrd for ProcDesc {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ProcDesc {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.sockets, self.pid, &self.name).cmp(&(&other.sockets, other.pid, &other.name))
    }
}
