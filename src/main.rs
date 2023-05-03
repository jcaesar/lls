mod netlink;
mod procs;
mod sockets_procfs;
mod termtree;

use anyhow::Result;
use itertools::Itertools;
use netlink::sock::{Family, SockInfo};
use procfs::process::all_processes;
use std::{
    collections::BTreeMap,
    env::{args, var_os},
    io::{stdout, BufWriter, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
};
use users::UsersCache;

pub type Ino = u64;

fn main() -> Result<()> {
    if args().len() > 1 {
        print!("{}", include_str!("help.txt"));
        return Ok(());
    }

    let users_cache = UsersCache::new();
    let (interfaces, local_routes) = interfaces_routes();
    let socks = netlink::sock::all_sockets(&interfaces, &local_routes); // TODO no clone
    let mut socks = match socks {
        Ok(socks) => socks,
        Err(netlink_err) => match sockets_procfs::all_sockets(&interfaces, &local_routes) {
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
    let mut lps = all_processes()?
        .filter_map(|p| procs::ProcDesc::inspect_ps(p, &mut socks, &users_cache, self_user_ns).ok())
        .filter(|p| !p.sockets.is_empty())
        .collect::<Vec<_>>();
    lps.iter_mut().for_each(|p| p.sockets.sort());
    lps.sort();
    for pd in lps {
        output.node(
            if let Some(name) = pd.name {
                format!("{name} (pid {} user {})", pd.pid, pd.user,)
            } else {
                format!("pid {} user {}", pd.pid, pd.user,)
            },
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
        output.node(format!("??? (user {uid})",), sockets_tree(socks));
    }
    let stdout = &mut BufWriter::new(stdout());
    let size = terminal_size::terminal_size().map(|(terminal_size::Width(w), _)| w.into());
    let color = size.is_some() && var_os("NO_COLOR").is_none();
    output.render(size, color, &mut |s| {
        stdout.write_all(s).expect("stdout shut")
    });

    Ok(())
}

fn interfaces_routes() -> (std::collections::HashMap<u32, String>, netlink::route::Rtbl) {
    let Ok(ref route_socket) = netlink::route::socket() else { return Default::default() };
    let interfaces = netlink::route::interface_names(route_socket).unwrap_or_default();
    let local_routes = netlink::route::local_routes(route_socket).unwrap_or_default();
    (interfaces, local_routes)
}

fn sockets_tree<'a>(
    sockets: impl IntoIterator<Item = impl Deref<Target = SockInfo<'a>>>,
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
            for sock in socks {
                match (sock.family, sock.iface) {
                    (Family::Both, _) => sout.leaf("*".into()),
                    (_, Some(ifname)) => sout.leaf(format!("{} ({ifname})", sock.addr)),
                    _ => sout.leaf(format!("{}", sock.addr)),
                };
            }
        }
        pout.node(format!(":{port} {proto}"), sout);
    }
    pout
}
