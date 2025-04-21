use super::Ino;
use crate::{
    netlink::sock::{Family, Protocol, SockInfo},
    IfaceInfo, IfaceName,
};
use anyhow::{Context, Result};
use std::collections::HashMap;

pub fn all_sockets<'i>(
    IfaceInfo {
        id2name: interfaces,
        local_routes,
        ..
    }: &'i IfaceInfo,
) -> Result<HashMap<Ino, SockInfo<'i>>> {
    eprintln!("WARNING: Falling back to parsing info from procfs, limited to TCP and UDP");
    let mut ret = HashMap::new();
    let mut errs = Vec::new();
    let mut one_success = false;

    macro_rules! save {
        ($fami:ident, $proto:ident, $file:ident) => {
            let file = procfs::net::$file()
                .context(concat!("Error parsing /proc/net/", stringify!($file)));
            match file {
                Ok(s) => {
                    one_success |= true;
                    s.into_iter().for_each(|s| {
                        if s.remote_address.port() == 0 {
                            ret.insert(
                                s.inode,
                                SockInfo {
                                    family: Family::$fami,
                                    protocol: Protocol::$proto,
                                    port: s.local_address.port(),
                                    addr: s.local_address.ip(),
                                    uid: s.uid,
                                    ino: s.inode,
                                    iface: local_routes
                                        .route(s.local_address.ip())
                                        .and_then(|iface| interfaces.get(&iface))
                                        .map(|s| IfaceName::LocalRoute(&**s))
                                        .unwrap_or(IfaceName::None),
                                },
                            );
                        }
                    })
                }
                Err(e) => errs.push(e),
            };
        };
    }
    save!(V6, UDP, udp6);
    save!(V6, TCP, tcp6);
    save!(V4, UDP, udp);
    save!(V4, TCP, tcp);

    match errs.is_empty() {
        true => Ok(ret),
        false => {
            for e in errs {
                eprintln!("{}", e);
            }
            match one_success {
                true => Ok(ret),
                false => anyhow::bail!("No success while parsing procfs"),
            }
        }
    }
}
