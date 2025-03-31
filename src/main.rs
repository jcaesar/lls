mod netlink;
mod options;
mod procs;
mod sockets_procfs;
mod termtree;

use anyhow::Result;
use itertools::Itertools;
use netlink::{
    sock::{Family, SockInfo},
    wg::wireguards,
};
use procfs::process::all_processes;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env::var_os,
    io::{stdout, BufWriter, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
};
use uzers::{Users as _, UsersCache};

pub type Ino = u64;

fn main() -> Result<()> {
    let users_cache = UsersCache::new();
    let iface_info = interfaces_routes();

    let filters = options::parse_args(&iface_info, &users_cache)?;

    let socks = netlink::sock::all_sockets(&iface_info); // TODO no clone, pass filters
    let mut socks = match socks {
        Ok(socks) => socks,
        Err(netlink_err) => match sockets_procfs::all_sockets(&iface_info) {
            Ok(socks) => socks,
            Err(proc_err) => {
                eprintln!(
                    "{}",
                    netlink_err.context("Get listening sockets from netlink")
                );
                eprintln!("{}", proc_err.context("Get listening sockets from netlink"));
                anyhow::bail!("Failed to get socket data");
            }
        },
    };
    let mut output = termtree::Tree::new();
    let self_user_ns = procs::get_user_ns(&procs::ourself()?).ok();

    // output known processes/sockets
    let mut lps = all_processes()?
        .filter_map(|p| procs::ProcDesc::inspect_ps(p, &mut socks, &users_cache, self_user_ns).ok())
        .filter(|p| !p.sockets.is_empty())
        .collect::<Vec<_>>();
    lps.iter_mut().for_each(|p| p.sockets.sort());
    lps.sort();
    for pd in lps {
        if filters.accept_process(&pd) {
            output.node(
                if let Some(name) = pd.name {
                    format!("{name} (pid {} user {})", pd.pid, pd.user,)
                } else {
                    format!("pid {} user {}", pd.pid, pd.user,)
                },
                sockets_tree(&pd.sockets, &filters),
            );
        }
    }

    // output wireguards
    let mut interface_sockets = HashMap::<_, Vec<_>>::new();
    socks.retain(|_sockid, sockinfo| {
        let mut retain = true;
        for &(if_id, port) in &iface_info.interface_ports {
            if port == sockinfo.port {
                retain = false;
                interface_sockets
                    .entry(if_id)
                    .or_default()
                    .push(sockinfo.to_owned());
            }
        }
        retain
    });
    for (if_id, socks) in &interface_sockets {
        if filters.accept_wg() {
            let name = match iface_info.id2name.get(if_id) {
                Some(ifname) => format!("[network interface {ifname}]"),
                None => format!("[network interface #{if_id}]"),
            };
            output.node(name, sockets_tree(socks, &filters));
        }
    }

    // output unknown sockets
    let mut socks = socks
        .values()
        .into_group_map_by(|s| s.uid)
        .into_iter()
        .collect::<Vec<_>>();
    socks.iter_mut().for_each(|(_, x)| x.sort());
    socks.sort_by_cached_key(|t| t.1.clone());
    match filters.cmd.is_empty() && filters.pid.is_empty() {
        true => {
            for (uid, socks) in socks {
                if filters.accept_user(uid) {
                    // Non-root users often have nothing else to work with, so
                    // print user name even when we don't know the correct same namespace
                    let user = (uzers::get_effective_uid() != 0)
                        .then(|| users_cache.get_user_by_uid(uid))
                        .flatten();
                    let proc_desc = match user {
                        Some(user) => {
                            let name = user.name().to_string_lossy();
                            format!("??? (user {uid}/{name}?)")
                        }
                        None => format!("??? (user {uid})"),
                    };
                    output.node(proc_desc, sockets_tree(socks, &filters));
                }
            }
        }
        false => {
            if !socks.is_empty() {
                eprintln!("WARNING: Some listening sockets hidden:");
                eprintln!("Not all sockets could not be matched to a process, process-based filtering not fully possible.");
            }
        }
    }

    let stdout = &mut BufWriter::new(stdout());
    let size = terminal_size::terminal_size().map(|(terminal_size::Width(w), _)| w.into());
    let color = size.is_some() && var_os("NO_COLOR").is_none();
    output.render(size, color, &mut |s| {
        stdout.write_all(s).expect("stdout shut")
    });

    Ok(())
}

#[derive(Default)]
struct IfaceInfo {
    id2name: HashMap<u32, String>,
    interface_ports: Vec<(u32, u16)>,
    local_routes: netlink::route::Rtbl,
}

fn interfaces_routes() -> IfaceInfo {
    let Ok(ref route_socket) = netlink::route::socket() else {
        return Default::default();
    };
    let netlink::route::Interfaces {
        id2name,
        wireguard_ids,
        vxlan_ports,
    } = netlink::route::interface_names(route_socket).unwrap_or_default();
    let local_routes = netlink::route::local_routes(route_socket).unwrap_or_default();
    let wireguard_ports = wireguards(&wireguard_ids).unwrap_or_default();
    IfaceInfo {
        id2name,
        interface_ports: wireguard_ports
            .into_iter()
            .chain(vxlan_ports.into_iter())
            .collect(),
        local_routes,
    }
}

fn sockets_tree<'a>(
    sockets: impl IntoIterator<Item = impl Deref<Target = SockInfo<'a>> + std::cmp::Ord>,
    filter: &options::Filters,
) -> termtree::Tree {
    let mut pout = termtree::Tree::new();
    let mut groups = BTreeMap::<_, Vec<_>>::new();
    for s in sockets {
        groups.entry((s.port, s.protocol)).or_default().push(s);
    }
    for ((port, proto), socks) in groups {
        let mut sout = termtree::Tree::new();
        if socks.iter().map(|s| s.addr).sorted().collect::<Vec<_>>()
            == [
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ]
        {
            sout.leaf("0.0.0.0 + ::".into());
        } else {
            let socks = socks
                .iter()
                .filter(|sock| filter.accept_addr(sock.addr))
                .collect::<BTreeSet<_>>();
            for sock in socks {
                match (sock.family, sock.iface) {
                    (Family::Both, _) => sout.leaf("*".into()),
                    (_, Some(ifname)) => sout.leaf(format!("{} ({ifname})", sock.addr)),
                    _ => sout.leaf(format!("{}", sock.addr)),
                };
            }
        }
        if filter.accept_port(port) && filter.accept_proto(proto) {
            pout.node(format!(":{port} {proto}"), sout);
        }
    }
    pout
}
