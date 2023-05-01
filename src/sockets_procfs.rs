use super::Ino;
use crate::netlink::{
    route::Rtbl,
    sock::{Family, Protocol, SockInfo},
};
use anyhow::Result;
use std::collections::HashMap;

pub fn all_sockets<'i>(
    interfaces: &'i HashMap<u32, String>,
    local_routes: &Rtbl,
) -> Result<HashMap<Ino, SockInfo<'i>>> {
    eprintln!("WARNING: Falling back to parsing info from procfs, limited to TCP and UDP");
    let mut ret = HashMap::new();
    let mut errs = Vec::new();

    macro_rules! save {
        ($fami:ident, $proto:ident, $file:ident) => {
            match procfs::net::$file() {
                Ok(s) => s.into_iter().for_each(|s| {
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
                                    .map(|s| &**s),
                            },
                        );
                    }
                }),
                Err(e) => errs.push(e),
            };
        };
    }
    save!(V6, UDP, udp6);
    save!(V6, TCP, tcp6);
    save!(V4, UDP, udp);
    save!(V4, TCP, tcp);

    Ok(ret)
}
