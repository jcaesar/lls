use super::netlink::sock::SockInfo;
use crate::Ino;
use anyhow::{Context, Result};
use procfs::process::Process;
use std::{collections::HashMap, ffi::OsString, os::unix::prelude::OsStringExt, path::PathBuf};
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
        self_user_ns: Option<u64>,
    ) -> Result<ProcDesc<'a>> {
        let p = p?;
        let name = ps_name(&p);
        let user = user_names
            .get_user_by_uid(p.uid()?)
            .filter(|_| get_user_ns(&p).ok() == self_user_ns)
            .map_or_else(
                || format!("{}", p.uid().unwrap()),
                |u| u.name().to_string_lossy().into_owned(),
            );
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
}

fn ps_name(p: &Process) -> Option<String> {
    let comm = &p.stat().ok().map(|s| remove_paren(s.comm));
    let exe = &p.exe().ok();
    let cmdline = &p.cmdline().ok();
    let name = comm
        .clone()
        .or_else(|| {
            // I considered checking whether to check if the exe file_name is on $PATH
            // and print the whole path if not. Nah.
            exe.as_ref()
                .and_then(|p| p.file_name().map(|p| p.to_string_lossy().into_owned()))
        })
        .or(cmdline.as_ref().and_then(|v| v.get(0).cloned()));
    if let py @ Some(_) = py_ps_name(&name, comm, exe, cmdline) {
        py
    } else {
        name
    }
}

fn py_ps_name(
    name: &Option<String>,
    comm: &Option<String>,
    exe: &Option<PathBuf>,
    cmdline: &Option<Vec<String>>,
) -> Option<String> {
    // I'm not entirely sure this is safe against python adding more options in the future
    let has_arg = ["--check-hash-based-pycs", "-m", "-Q", "-W", "-X"]; // Deliberately exclude -c
    let no_arg = [
        "-3", "-b", "-B", "-d", "-E", "-h", "-i", "-I", "-O", "-OO", "-q", "-R", "-s", "-S", "-t",
        "-u", "-v", "-V", "-x",
    ];
    let interpreter = "python";
    let extension = ".py";
    let name = name.as_ref()?;
    let cmdline = cmdline.as_ref()?;
    if !looks_ish(interpreter, comm.as_ref()?)
        || !looks_ish(interpreter, &exe.as_ref()?.file_name()?.to_string_lossy())
    {
        None?
    }
    let mut cmdline = cmdline.iter();
    if !looks_ish(interpreter, cmdline.next()?) {
        None?
    }
    while let Some(arg) = cmdline.next() {
        if arg == "--" {
            return cmdline.next().cloned();
        } else if arg == "-m" {
            return Some(format!("{name} -m {}", cmdline.next()?));
        } else if has_arg.contains(&arg.as_str()) {
            cmdline.next();
        } else if no_arg.contains(&arg.as_str()) {
        } else if arg.starts_with("-") {
            return None; // Unknown arg, better give up
        } else {
            if arg.ends_with(extension) {
                return Some(arg.clone());
            } else {
                return Some(format!("{name} {arg}"));
            }
        }
    }
    None
}

fn looks_ish(name: &str, comm: &str) -> bool {
    if let Some(suffix) = comm.strip_prefix(name) {
        suffix.chars().all(|c| c.is_numeric() || c == '.')
    } else {
        false
    }
}

fn remove_paren(x: String) -> String {
    x.strip_prefix("(")
        .and_then(|x| x.strip_suffix(")"))
        .map(|x| x.into())
        .unwrap_or(x)
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

pub fn get_user_ns(p: &Process) -> Result<u64> {
    Ok(p.namespaces()
        .context("Namespaces inaccessible")?
        .get(&OsString::from_vec(b"user".to_vec()))
        .context("No user ns")?
        .identifier)
}

pub fn ourself() -> Result<Process> {
    Ok(procfs::process::Process::myself()?)
}
