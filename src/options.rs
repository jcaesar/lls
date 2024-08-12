use crate::netlink::route::Prefix;
use crate::netlink::sock::Protocol;
use crate::procs;
use crate::IfaceInfo;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use std;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env::args;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::process::exit;
use uzers::Users;
use uzers::UsersCache;

struct Arg(Option<char>, char, &'static [&'static str]);
static ARGS: [Arg; 6] = [
    Arg(None, 'a', &["addr", "address", "prefix"]),
    Arg(Some(':'), 'p', &["port"]),
    Arg(Some('%'), 'P', &["pid", "process-id"]),
    Arg(Some('/'), 'c', &["cmd", "command"]),
    Arg(None, 'u', &["user"]),
    Arg(None, 'i', &["iface", "interface"]),
];

#[derive(Debug, Default)]
pub struct Filters {
    pub port: Vec<RangeInclusive<u16>>, // :
    pub cmd: Vec<String>,               // /
    pub pid: Vec<i32>,                  // %
    pub proto: HashSet<Protocol>,       // tcp/udp/...
    pub pfxs: Vec<Prefix>,              // prefix or interface name
    pub user: Vec<u32>,
}

impl Filters {
    pub fn accept_process(&self, pd: &procs::ProcDesc) -> bool {
        self.accept_pid(pd.pid) && self.accept_cmd(pd) && self.accept_user(pd.uid)
    }

    pub fn accept_pid(&self, pid: i32) -> bool {
        self.pid.is_empty() || self.pid.contains(&pid)
    }

    pub fn accept_user(&self, uid: u32) -> bool {
        self.user.is_empty() || self.user.contains(&uid)
    }

    pub fn accept_cmd(&self, pd: &procs::ProcDesc) -> bool {
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

    pub fn accept_port(&self, port: u16) -> bool {
        self.port.is_empty() || self.port.iter().any(|r| r.contains(&port))
    }

    pub fn accept_proto(&self, proto: Protocol) -> bool {
        self.proto.is_empty() || self.proto.contains(&proto)
    }

    pub fn accept_addr(&self, addr: IpAddr) -> bool {
        self.pfxs.is_empty()
            || self.pfxs.iter().any(|pfx| pfx.matches(addr))
            || addr.is_unspecified()
    }

    pub(crate) fn accept_wg(&self) -> bool {
        self.cmd.is_empty() && self.pid.is_empty()
    }
}

pub fn match_arg(arg: &str, args: &mut std::env::Args) -> Result<Option<(char, String)>> {
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

pub fn parse_args(
    IfaceInfo {
        id2name: ifaces,
        local_routes,
        ..
    }: &IfaceInfo,
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
                    let uids = [uzers::get_current_uid(), uzers::get_effective_uid()];
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
