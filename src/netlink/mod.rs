pub mod route;
pub mod sock;

use anyhow::Result;
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
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
    socket.send(&buf[..], 0).unwrap();
    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    loop {
        let size = socket.recv(&mut &mut receive_buffer[..], 0).unwrap();

        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet: NetlinkMessage<T> = NetlinkMessage::deserialize(bytes).unwrap();
            match rx_packet.payload {
                NetlinkPayload::Done => return Ok(()),
                NetlinkPayload::InnerMessage(inner) => recv(inner),
                _ => todo!(),
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
}
