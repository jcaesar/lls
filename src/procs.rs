use super::netlink::sock::SockInfo;
use crate::Ino;
use anyhow::Result;
use procfs::process::Process;
use std::collections::HashMap;
use std::path::PathBuf;
use users::{Users, UsersCache};

pub type Pid = i32;

#[derive(Debug, PartialEq, Eq)]
pub struct ProcDesc<'a> {
    pub pid: Pid,
    pub user: String,
    pub name: Option<String>,
    pub sockets: Vec<SockInfo<'a>>,
}

impl<'a> ProcDesc<'a> {
    pub fn inspect_ps(
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

    pub fn ps_name(p: &Process) -> Option<String> {
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
