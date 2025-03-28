pub mod route;
pub mod sock;
pub mod wg;

use anyhow::{Context, Result};
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};
use netlink_sys::Socket;

fn drive_req<T>(
    mut packet: NetlinkMessage<T>,
    socket: &Socket,
    mut recv: impl FnMut(T),
) -> Result<()>
where
    T: NetlinkSerializable,
    T: NetlinkDeserializable,
{
    packet.finalize();
    let mut buf = vec![0; packet.header.length as usize];
    assert!(buf.len() == packet.buffer_len());
    packet.serialize(&mut buf[..]);
    socket.send(&buf[..], 0).context("Netlink send error")?;
    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    loop {
        let size = socket
            .recv(&mut &mut receive_buffer[..], 0)
            .context("Netlink receive failure")?;

        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet: NetlinkMessage<T> = NetlinkMessage::deserialize(bytes)
                .context("Netlink message format not recognized")?;
            match rx_packet.payload {
                NetlinkPayload::Done(_) => return Ok(()),
                NetlinkPayload::InnerMessage(inner) => recv(inner),
                NetlinkPayload::Error(err) => match err.code {
                    Some(_) => return Err(err.to_io()).context("Netlink error"),
                    None => return Ok(()),
                },
                p => todo!("Unexpected netlink payload {:?}", p.message_type()),
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
}

pub fn nl_hdr_flags(flags: u16) -> NetlinkHeader {
    let mut header = NetlinkHeader::default();
    header.flags = flags;
    header
}
