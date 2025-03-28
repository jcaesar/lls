use super::netlink::sock::SockInfo;
use crate::Ino;
use anyhow::{Context, Result};
use procfs::process::Process;
use std::{
    collections::HashMap, ffi::OsString, ops::ControlFlow, os::unix::prelude::OsStringExt,
    path::PathBuf,
};
use uzers::{Users, UsersCache};

pub type Pid = i32;

#[derive(Debug, PartialEq, Eq)]
pub struct ProcDesc<'a> {
    pub pid: Pid,
    pub user: String,
    pub uid: u32,
    pub name: Option<String>,
    pub info: ProcNamePre,
    pub sockets: Vec<SockInfo<'a>>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcNamePre {
    pub name: Option<String>,
    pub exe: Option<PathBuf>,
    pub cmdline: Option<Vec<String>>,
}

impl<'a> ProcDesc<'a> {
    pub fn inspect_ps(
        p: Result<Process, procfs::ProcError>,
        socks: &mut HashMap<Ino, SockInfo<'a>>,
        user_names: &UsersCache,
        self_user_ns: Option<u64>,
    ) -> Result<ProcDesc<'a>> {
        let p = p?;
        let (name, info) = ps_name(&p);
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
            info,
            uid: p.uid()?,
        })
    }
}

fn ps_name(p: &Process) -> (Option<String>, ProcNamePre) {
    let exe = p.exe().ok();
    let cmdline = p.cmdline().ok();
    // I considered checking whether to check if the exe file_name is on $PATH
    // and print the whole path if not. Nah.
    let name = exe
        .as_ref()
        .and_then(|p| p.file_name().map(|p| p.to_string_lossy().into_owned()))
        .or_else(|| cmdline.as_ref().and_then(|v| v.get(0).cloned()));
    let proc_name_pre = ProcNamePre { exe, cmdline, name };
    let name = if let py @ Some(_) = py_ps_name(&proc_name_pre) {
        py
    } else if let lua @ Some(_) = lua_ps_name(&proc_name_pre) {
        lua
    } else if let java @ Some(_) = java_ps_name(&proc_name_pre) {
        java
    } else if let node @ Some(_) = node_ps_name(&proc_name_pre) {
        node
    } else {
        proc_name_pre.name.clone()
    };
    (name, proc_name_pre)
}

fn java_ps_name(proc_name_pre: &ProcNamePre) -> Option<String> {
    let special = &|arg: &str, next: Option<&str>| {
        if arg == "-jar" {
            ControlFlow::Break(
                next.filter(|jar| jar.ends_with(".jar"))
                    .map(|s| s.to_owned()),
            )
        } else {
            ControlFlow::Continue(())
        }
    };
    interpreter_ps_name(
        "java",
        None,
        &["-classpath", "-cp"],
        &["-d32", "-d64"],
        &[
            "-javaagent:",
            "-agentlib:",
            "-agentpath",
            "-verbose:",
            "-D",
            "-X",
        ],
        proc_name_pre,
        special,
    )
}

fn lua_ps_name(proc_name_pre: &ProcNamePre) -> Option<String> {
    interpreter_ps_name(
        "lua",
        Some(".lua"),
        &["-l"],
        &["-i", "-E"],
        &[],
        proc_name_pre,
        &|_, _| ControlFlow::Continue(()),
    )
}

fn py_ps_name(proc_name_pre: &ProcNamePre) -> Option<String> {
    // I'm not entirely sure this is safe against python adding more options in the future
    let has_arg = &["--check-hash-based-pycs", "-m", "-Q", "-W", "-X"]; // Deliberately exclude -c
    let no_arg = &[
        "-3", "-b", "-B", "-d", "-E", "-h", "-i", "-I", "-O", "-OO", "-q", "-R", "-s", "-S", "-t",
        "-u", "-v", "-V", "-x",
    ];
    let special = &|arg: &str, next: Option<&str>| {
        if arg == "-m" {
            ControlFlow::Break((|| {
                Some(format!("{} -m {}", proc_name_pre.name.as_ref()?, next?))
            })())
        } else {
            ControlFlow::Continue(())
        }
    };
    interpreter_ps_name(
        "python",
        Some(".py"),
        has_arg,
        no_arg,
        &[],
        proc_name_pre,
        special,
    )
}

fn node_ps_name(proc_name_pre: &ProcNamePre) -> Option<String> {
    let has_arg = &["-C", "--conditions", "-r", "--require"];
    let no_arg = &[
        "--abort-on-uncaught-exception",
        "--completion-bash",
        "--cpu-prof",
        "--disallow-code-generation-from-strings",
        "--enable-fips",
        "--enable-source-maps",
        "--experimental-global-webcrypto",
        "--experimental-import-meta-resolve",
        "--experimental-network-imports",
        "--experimental-policy",
        "--experimental-shadow-realm",
        "--no-experimental-fetch",
        "--no-experimental-global-customevent",
        "--no-experimental-global-webcrypto",
        "--no-experimental-repl-await",
        "--experimental-vm-modules",
        "--experimental-wasi-unstable-preview1",
        "--experimental-wasm-modules",
        "--force-context-aware",
        "--force-fips",
        "--frozen-intrinsics",
        "--heap-prof",
        "--insecure-http-parser",
        "--jitless",
        "--napi-modules",
        "--no-deprecation",
        "--no-extra-info-on-fatal-exception",
        "--no-force-async-hooks-checks",
        "--no-addons",
        "--no-global-search-paths",
        "--no-warnings",
        "--node-memory-debug",
        "--pending-deprecation",
        "--preserve-symlinks",
        "--preserve-symlinks-main",
        "--prof",
        "--prof-process",
        "--report-compact",
        "--report-on-fatalerror",
        "--report-on-signal",
        "--report-signal",
        "--report-uncaught-exception",
        "--throw-deprecation",
        "--tls-max-v1.2",
        "--tls-max-v1.3",
        "--tls-min-v1.0",
        "--tls-min-v1.1",
        "--tls-min-v1.2",
        "--tls-min-v1.3",
        "--trace-atomics-wait",
        "--trace-deprecation",
        "--trace-event-categories categories",
        "--trace-event-file-pattern pattern",
        "--trace-events-enabled",
        "--trace-exit",
        "--trace-sigint",
        "--trace-sync-io",
        "--trace-tls",
        "--trace-uncaught",
        "--trace-warnings",
        "--track-heap-objects",
        "--update-assert-snapshot",
        "--use-bundled-ca",
        "--use-openssl-ca",
        "--v8-options",
        "--zero-fill-buffers",
        "-c",
        "--check",
        "-i",
        "--interactive",
    ];
    let prefixes = &[
        "--disable-proto=",
        "--experimental-loader=",
        "--heapsnapshot-near-heap-limit=",
        "--heapsnapshot-signal=",
        "--icu-data-dir=",
        "--input-type=",
        "--inspect-brk=",
        "--inspect-port=",
        "--inspect-publish-uid=",
        "--inspect=",
        "--max-http-header-size=",
        "--openssl-config=",
        "--policy-integrity=",
        "--redirect-warnings=",
        "--secure-heap=",
        "--secure-heap-min=",
        "--title=",
        "--tls-cipher-list=",
        "--tls-keylog=",
        "--unhandled-rejections=",
        "--use-largepages=",
        "--v8-pool-size=",
    ];
    interpreter_ps_name(
        "node",
        None, // Too many ways to run js
        has_arg,
        no_arg,
        prefixes,
        proc_name_pre,
        &|_, _| ControlFlow::Continue(()),
    )
}

fn interpreter_ps_name(
    interpreter: &str,
    extension: Option<&str>,
    has_arg: &[&str],
    no_arg: &[&str],
    prefix_arg: &[&str],
    proc_name_pre: &ProcNamePre,
    special: &impl Fn(&str, Option<&str>) -> ControlFlow<Option<String>>,
) -> Option<String> {
    let name = proc_name_pre.name.as_ref()?;
    let cmdline = proc_name_pre.cmdline.as_ref()?;
    if !looks_ish(interpreter, proc_name_pre.name.as_ref()?)
        || !looks_ish(
            interpreter,
            &proc_name_pre.exe.as_ref()?.file_name()?.to_string_lossy(),
        )
    {
        None?
    }
    let mut cmdline = cmdline.iter().peekable();
    if !looks_ish(interpreter, cmdline.next()?) {
        None?
    }
    while let Some(arg) = cmdline.next() {
        if let ControlFlow::Break(v) = special(arg, cmdline.peek().map(|x| x.as_str())) {
            return v;
        } else if arg == "--" {
            return cmdline.next().cloned();
        } else if has_arg.contains(&arg.as_str()) {
            cmdline.next();
        } else if no_arg.contains(&arg.as_str()) {
        } else if prefix_arg.iter().any(|&pfx| arg.starts_with(pfx)) {
        } else if arg.starts_with('-') {
            return None; // Unknown arg, better give up
        } else {
            match extension {
                Some(extension) if arg.ends_with(extension) => {
                    return Some(arg.clone());
                }
                _ => {
                    return Some(format!("{name} {arg}"));
                }
            }
        }
    }
    None
}

fn looks_ish(name: &str, comm: &str) -> bool {
    let comm = &comm[comm.rfind('/').map_or(0, |p| p + 1)..];
    if let Some(suffix) = comm.strip_prefix(name) {
        suffix.chars().all(|c| c.is_numeric() || c == '.')
    } else {
        false
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

pub fn get_user_ns(p: &Process) -> Result<u64> {
    Ok(p.namespaces()
        .context("Namespaces inaccessible")?
        .0
        .get(&OsString::from_vec(b"user".to_vec()))
        .context("No user ns")?
        .identifier)
}

pub fn ourself() -> Result<Process> {
    Ok(procfs::process::Process::myself()?)
}

#[cfg(test)]
mod test {
    use super::ProcNamePre;

    #[test]
    fn py_ps_name_synapse() {
        let cmdline = [
            "/usr/bin/python3",
            "-m",
            "synapse.app.homeserver",
            "--config-path=/etc/synapse/homeserver.yaml",
        ]
        .into_iter()
        .map(|s| s.to_owned())
        .collect();
        let name = super::py_ps_name(&ProcNamePre {
            name: Some("python".into()),
            exe: Some("/usr/bin/python3".into()),
            cmdline: Some(cmdline),
        });
        assert_eq!(name.as_deref(), Some("python -m synapse.app.homeserver"));
    }

    #[test]
    fn py_ps_name_mms() {
        let cmdline = ["/usr/bin/python", "/home/self/MMS/app.py"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect();

        let name = super::py_ps_name(&ProcNamePre {
            name: Some("python".into()),
            exe: Some("/usr/bin/python3.10".into()),
            cmdline: Some(cmdline),
        });
        assert_eq!(name.as_deref(), Some("/home/self/MMS/app.py"));
    }

    #[test]
    fn java_ps_name_flink() {
        let cmdline = [
            "/opt/java/openjdk/bin/java",
            "-Xmx1073741824",
            "-Xms1073741824",
            "-XX:MaxMetaspaceSize=268435456",
            "-Dlog.file=/opt/flink/log/flink--standalonesession-0-pride.log",
            "-Dlog4j.configuration=file:/opt/flink/conf/log4j-console.properties",
            "-Dlog4j.configurationFile=file:/opt/flink/conf/log4j-console.properties",
            "-Dlogback.configurationFile=file:/opt/flink/conf/logback-console.xml",
            "-classpath",
            "/opt/flink/lib/flink-cep-1.16.0.jar:/opt…::::",
            "org.apache.flink.runtime.entrypoint.StandaloneSessionClusterEntrypoint",
            "-D",
            "jobmanager.memory.off-heap.size=134217728b",
            "-D",
            "jobmanager.memory.jvm-overhead.min=201326592b",
            "-D",
            "jobmanager.memory.jvm-metaspace.size=268435456b",
            "-D",
            "jobmanager.memory.heap.size=1073741824b",
            "-D",
            "jobmanager.memory.jvm-overhead.max=201326592b",
            "--configDir",
            "/opt/flink/conf",
            "--executionMode",
            "cluster",
        ]
        .into_iter()
        .map(|s| s.to_owned())
        .collect();
        let name = super::java_ps_name(&ProcNamePre {
            name: Some("java".to_owned()),
            exe: Some("/opt/java/openjdk/bin/java".into()),
            cmdline: Some(cmdline),
        });
        assert_eq!(
            name.as_deref(),
            Some("java org.apache.flink.runtime.entrypoint.StandaloneSessionClusterEntrypoint")
        );
    }

    #[test]
    fn node_ps_name_simple() {
        let cmdline = ["node", "serve.js"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect();

        let name = super::node_ps_name(&ProcNamePre {
            name: Some("node".into()),
            exe: Some("/usr/bin/node".into()),
            cmdline: Some(cmdline),
        });
        assert_eq!(name.as_deref(), Some("node serve.js"));
    }
}
