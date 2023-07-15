mod netlink;
mod procs;
mod sockets_procfs;
mod termtree;

use anyhow::{bail, Context, Result};
use itertools::Itertools;
use netlink::{
    route::{Prefix, Rtbl},
    sock::{Family, Protocol, SockInfo},
};
use procfs::process::all_processes;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env::{args, var_os},
    io::{stdout, BufWriter, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{Deref, RangeInclusive},
    process::exit,
};
use users::{Users, UsersCache};

pub type Ino = u64;

#[derive(Debug, Default)]
struct Filters {
    port: Vec<RangeInclusive<u16>>, // :
    cmd: Vec<String>,               // /
    pid: Vec<i32>,                  // %
    proto: HashSet<Protocol>,       // tcp/udp/...
    pfxs: Vec<Prefix>,              // prefix or interface name
    user: Vec<u32>,
}
impl Filters {
    fn accept_process(&self, pd: &procs::ProcDesc) -> bool {
        self.accept_pid(pd.pid) && self.accept_cmd(pd) && self.accept_user(pd.uid)
    }

    fn accept_pid(&self, pid: i32) -> bool {
        self.pid.is_empty() || self.pid.contains(&pid)
    }

    fn accept_user(&self, uid: u32) -> bool {
        self.user.is_empty() || self.user.contains(&uid)
    }

    fn accept_cmd(&self, pd: &procs::ProcDesc) -> bool {
        self.cmd.is_empty()
            || self.cmd.iter().any(|cmd| {
                let cmd = cmd.to_lowercase();
                let check = |x: &str| x.to_lowercase().contains(&cmd);
                let check_option = |x: &Option<String>| x.as_deref().is_some_and(check);
                check_option(&pd.name)
                    || check_option(&pd.info.name)
                    || check_option(&pd.info.comm)
                    || pd
                        .info
                        .exe
                        .as_deref()
                        .is_some_and(|s| check(&s.to_string_lossy()))
                    || pd
                        .info
                        .cmdline
                        .as_ref()
                        .is_some_and(|cmdline| cmdline.iter().any(|s| check(s)))
            })
    }

    fn accept_port(&self, port: u16) -> bool {
        self.port.is_empty() || self.port.iter().any(|r| r.contains(&port))
    }

    fn accept_proto(&self, proto: Protocol) -> bool {
        self.proto.is_empty() || self.proto.contains(&proto)
    }

    fn accept_addr(&self, addr: IpAddr) -> bool {
        self.pfxs.is_empty()
            || self.pfxs.iter().any(|pfx| pfx.matches(addr))
            || addr.is_unspecified()
    }
}

fn main() -> Result<()> {
    let users_cache = UsersCache::new();
    let (interfaces, local_routes) = interfaces_routes();

    let filters = parse_args(&interfaces, &local_routes, &users_cache)?;

    let socks = netlink::sock::all_sockets(&interfaces, &local_routes); // TODO no clone, pass filters
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
                    output.node(format!("??? (user {uid})",), sockets_tree(socks, &filters));
                }
            }
        }
        false => {
            eprintln!("WARNING: Some listening sockets hidden:");
            eprintln!("Not all sockets could not be matched to a process, process-based filtering not fully possible.");
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

struct Arg(Option<char>, char, &'static [&'static str]);
static ARGS: [Arg; 6] = [
    Arg(None, 'a', &["addr", "address", "prefix"]),
    Arg(Some(':'), 'p', &["port"]),
    Arg(Some('%'), 'P', &["pid", "process-id"]),
    Arg(Some('/'), 'c', &["cmd", "command"]),
    Arg(None, 'u', &["user"]),
    Arg(None, 'i', &["iface", "interface"]),
];

fn match_arg(arg: &str, args: &mut std::env::Args) -> Result<Option<(char, String)>> {
    for m in &ARGS {
        if let Some(abbrev) = m.0 {
            if let Some(arg) = arg.strip_prefix(abbrev).filter(|s| !s.is_empty()) {
                return Ok(Some((m.1, arg.into())));
            }
        }
        for (pfx, name) in
            std::iter::once(("-", m.1.to_string().as_str())).chain(m.2.iter().map(|&s| ("--", s)))
        {
            let f = format!("{pfx}{name}");
            if arg == f {
                return Ok(Some((
                    m.1,
                    args.next()
                        .with_context(|| format!("Argument to {f} is missing"))?,
                )));
            }
            if let Some(arg) = arg.strip_prefix(&format!("{f}=")) {
                return Ok(Some((m.1, arg.into())));
            }
            if let Some(arg) = arg.strip_prefix(&f) {
                return Ok(Some((m.1, arg.into())));
            }
        }
    }
    Ok(None)
}

fn parse_args(
    ifaces: &HashMap<u32, String>,
    local_routes: &Rtbl,
    users: &UsersCache,
) -> Result<Filters> {
    let ifaces = ifaces
        .iter()
        .map(|(&id, name)| (name, id))
        .collect::<HashMap<_, _>>();
    for arg in args() {
        if matches!(
            arg.as_str(),
            "-h" | "--help" | "help" | "-help" | "--h" | "-?"
        ) {
            print!("{}", include_str!("help.txt"));
            exit(0);
        }
    }
    let mut filters: Filters = Filters::default();
    let mut args = args();
    args.next().expect("Arg 0 missing");
    while let Some(arg) = args.next() {
        let normal_match = match_arg(&arg, &mut args)?;
        match normal_match {
            Some(('c', arg)) => filters.cmd.push(arg.to_owned()),
            Some(('P', arg)) => filters.pid.push(
                arg.parse()
                    .with_context(|| format!("Unable to parse pid filter {:?}", &arg))?,
            ),
            Some(('u', arg)) => {
                if let Some(user) = users.get_user_by_name(&arg) {
                    filters.user.push(user.uid())
                } else if let Ok(uid) = arg.parse() {
                    if users.get_user_by_uid(uid).is_none() {
                        eprintln!("WARNING: Unknown user id: {uid}");
                    }
                    filters.user.push(uid);
                } else {
                    bail!("Unknown user {arg}");
                }
            }
            Some(('p', arg)) => {
                let mut split = arg.splitn(2, '-');
                let start_port = split
                    .next()
                    .expect("Split iterator should always return at least one element");
                let end_port = split.next();
                let start_port: u16 = start_port.parse().with_context(|| {
                    format!(
                        "Parse port {}{:?} of range {:?}",
                        match end_port.is_some() {
                            true => "range start ",
                            false => "",
                        },
                        start_port,
                        &arg,
                    )
                })?;
                let end_port = match end_port {
                    Some(end_port) => end_port.parse().with_context(|| {
                        format!("Parse port range end {:?} of range {:?}", end_port, &arg)
                    })?,
                    None => start_port,
                };

                filters.port.push(match start_port <= end_port {
                    true => start_port..=end_port,
                    false => end_port..=start_port,
                });
            }
            Some(('i', arg)) => {
                if let Some(&ifaceid) = ifaces.get(&arg) {
                    for pfx in local_routes.for_iface(ifaceid) {
                        filters.pfxs.push(pfx);
                    }
                    continue;
                } else {
                    bail!("Unknown interface {arg}");
                }
            }
            Some(('a', arg)) => filters.pfxs.push(
                arg.parse()
                    .with_context(|| format!("Can't parse {arg:?} as prefix"))?,
            ),
            Some((c, _)) => {
                unreachable!("Argument parser bug - {c}");
            }
            None => {
                if matches!(arg.as_str(), "-s" | "--self") {
                    let uids = [users::get_current_uid(), users::get_effective_uid()];
                    filters.user.extend_from_slice(&uids);
                } else if let Some(Ok(proto)) = arg.strip_prefix("--").map(str::parse) {
                    filters.proto.insert(proto);
                } else if let Ok(proto) = arg.parse() {
                    filters.proto.insert(proto);
                } else if let Ok(prefix) = arg.parse() {
                    filters.pfxs.push(prefix);
                } else if let Some(&ifaceid) = ifaces.get(&arg) {
                    for pfx in local_routes.for_iface(ifaceid) {
                        filters.pfxs.push(pfx);
                    }
                } else if let Some(user) = users.get_user_by_name(&arg) {
                    filters.user.push(user.uid())
                } else {
                    bail!("Unknown argument: {arg:?}");
                }
            }
        }
    }
    Ok(filters)
}

fn interfaces_routes() -> (std::collections::HashMap<u32, String>, netlink::route::Rtbl) {
    let Ok(ref route_socket) = netlink::route::socket() else { return Default::default() };
    let interfaces = netlink::route::interface_names(route_socket).unwrap_or_default();
    let local_routes = netlink::route::local_routes(route_socket).unwrap_or_default();
    (interfaces, local_routes)
}

fn sockets_tree<'a>(
    sockets: impl IntoIterator<Item = impl Deref<Target = SockInfo<'a>>>,
    filter: &Filters,
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
                if filter.accept_addr(sock.addr) {
                    match (sock.family, sock.iface) {
                        (Family::Both, _) => sout.leaf("*".into()),
                        (_, Some(ifname)) => sout.leaf(format!("{} ({ifname})", sock.addr)),
                        _ => sout.leaf(format!("{}", sock.addr)),
                    };
                }
            }
        }
        if filter.accept_port(port) && filter.accept_proto(proto) {
            pout.node(format!(":{port} {proto}"), sout);
        }
    }
    pout
}
