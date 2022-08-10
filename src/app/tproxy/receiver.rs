use std::{io, pin::Pin};

use bytes::Bytes;
use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, trace, warn};

use crate::app::{
    tproxy::socket::Message,
    types::{ClientAddr, RemoteAddr, UdpPacket},
    AppContext,
};

use super::socket::{AsyncUdpSocket, MsgArrayBuffer};

pub(crate) struct TProxyReceiver {
    context: AppContext,
    tproxy_socket: AsyncUdpSocket,
}

impl TProxyReceiver {
    pub(crate) fn new(context: &AppContext) -> io::Result<Self> {
        let bind_addr = (context.cli_args.host, context.cli_args.port).into();
        let tproxy_socket = AsyncUdpSocket::bind_tproxy(&bind_addr)?;
        Ok(Self {
            context: context.clone(),
            tproxy_socket,
        })
    }

    pub(crate) fn incoming_packets(self) -> impl Stream<Item = UdpPacket> {
        let (sender, receiver) = mpsc::channel(16);
        tokio::spawn(async move {
            let mut buf: Pin<Box<MsgArrayBuffer<8, 2048>>> = MsgArrayBuffer::new();
            loop {
                buf.clear();
                self.tproxy_socket
                    .batch_recv(&mut buf)
                    .await
                    .expect("Error on read TProxy socket");
                if buf.len() > 1 {
                    // FIXME: remove it
                    debug!("Batch recv {} messages", buf.len());
                }
                for Message {
                    src_addr,
                    dst_addr,
                    buf,
                } in buf.iter()
                {
                    if let (Some(src), Some(dst)) = (src_addr, dst_addr) {
                        let client: ClientAddr = src.into();
                        let remote: RemoteAddr = dst.into();
                        trace!(
                            "Received from TProxy: {:?} => {:?}, {} bytes",
                            client,
                            remote,
                            buf.len(),
                        );
                        sender
                            .send((client, remote, Bytes::copy_from_slice(buf)))
                            .await
                            .expect("Error on send incoming packet");
                    } else {
                        warn!("Missing src/dst address from TProxy socket");
                    }
                }
            }
        });

        ReceiverStream::new(receiver)
    }
}
