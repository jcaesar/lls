use super::drive_req;
use anyhow::{Context, Result};
use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlMessage,
};
use netlink_packet_wireguard::{nlas::WgDeviceAttrs, Wireguard, WireguardCmd};
use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};
use std::collections::HashMap;

pub fn wireguards(interface_ids: &[u32]) -> Result<HashMap<u16, u32>> {
    if interface_ids.is_empty() {
        return Ok(Default::default());
    }

    let mut socket = Socket::new(NETLINK_GENERIC).context("Construct netlink generic socket")?;
    socket.bind_auto().context("Bind netlink generic socket")?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .context("Connect netlink generic socket")?;

    // Resolve wireguard family id.
    // genetlink can do this for me, but it's all async and tokio based.
    let mut packet = NetlinkMessage::new(
        NetlinkHeader::default(),
        GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName("wireguard".into())],
        })
        .into(),
    );
    packet.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    packet.header.sequence_number = 1;
    let mut family_id: Option<u16> = None;
    drive_req(packet, &socket, |inner| {
        for nla in inner.payload.nlas {
            if let GenlCtrlAttrs::FamilyId(id) = nla {
                family_id = Some(id);
            }
        }
    })
    .context("Get wireguard family")?;
    let family_id = family_id.context("Netlink wireguard family not found")?;

    let mut ret = HashMap::new();
    for &if_id in interface_ids {
        let mut payload = GenlMessage::from_payload(Wireguard {
            cmd: WireguardCmd::GetDevice,
            nlas: vec![WgDeviceAttrs::IfIndex(if_id)],
        });
        payload.set_resolved_family_id(family_id);
        let mut packet = NetlinkMessage::new(NetlinkHeader::default(), payload.into());
        packet.header.flags = NLM_F_DUMP | NLM_F_REQUEST | NLM_F_ACK;
        packet.header.sequence_number = 2;

        drive_req(packet, &socket, |inner| {
        for nla in inner.payload.nlas {
            if let WgDeviceAttrs::ListenPort(port) = nla {
                if let Some(other_id) = ret.insert(port, if_id) {
                    eprintln!("WARNING: Wireguard interfaces {if_id} and {other_id} seem to be listening on the same port {port}. Output may be inaccurate");
                    }
                }
            }
    })
    .context("Get wireguard ")?;
    }

    Ok(ret)
}
