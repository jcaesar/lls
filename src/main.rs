mod netlink;
mod termtree;

use anyhow::Result;
use itertools::Itertools;
use netlink::sock::{Family, SockInfo};
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
    let interfaces = netlink::route::interface_names().unwrap_or_default();
    let mut socks = netlink::sock::all_sockets(&interfaces)?;
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
        if socks.len() == 2
            && socks.iter().any(|s| s.addr == Ipv4Addr::UNSPECIFIED)
            && socks.iter().any(|s| s.addr == Ipv6Addr::UNSPECIFIED)
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

type Ino = u64;
type Pid = i32;
#[derive(Debug, PartialEq, Eq)]
struct ProcDesc<'a> {
    pid: Pid,
    user: String,
    name: Option<String>,
    sockets: Vec<SockInfo<'a>>,
}

impl<'a> ProcDesc<'a> {
    fn inspect_ps(
        p: Result<Process, procfs::ProcError>,
        socks: &mut HashMap<Ino, SockInfo<'a>>,
        user_names: &UsersCache,
    ) -> Result<ProcDesc<'a>> {
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

impl PartialOrd for ProcDesc<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ProcDesc<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.sockets, self.pid, &self.name).cmp(&(&other.sockets, other.pid, &other.name))
    }
}
