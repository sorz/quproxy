use std::io;

use bytes::Bytes;
use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::trace;

use crate::app::{types::UdpPacket, AppContext};

use super::socket::AsyncUdpSocket;

pub(crate) struct TProxyReceiver<S> {
    context: AppContext<S>,
    tproxy_socket: AsyncUdpSocket,
}

impl<S: Sync + Send + 'static> TProxyReceiver<S> {
    pub(crate) fn new(context: &AppContext<S>) -> io::Result<Self> {
        let bind_addr = (context.cli_args.host, context.cli_args.port).into();
        let tproxy_socket = AsyncUdpSocket::bind_tproxy(&bind_addr)?;
        Ok(Self {
            context: context.clone(),
            tproxy_socket,
        })
    }

    pub(crate) fn incoming_packets(self) -> impl Stream<Item = UdpPacket> {
        let (sender, receiver) = mpsc::channel(16);
        let mut buf = [0u8; 2048];
        tokio::spawn(async move {
            loop {
                let (n, client, remote) = self
                    .tproxy_socket
                    .recv_msg(&mut buf)
                    .await
                    .expect("Error on read TProxy socket");
                trace!(
                    "Received from TProxy: {:?} => {:?}, {} bytes",
                    client,
                    remote,
                    n
                );
                sender
                    .send((client, remote, Bytes::copy_from_slice(&buf[..n])))
                    .await
                    .expect("Error on send incoming packet");
            }
        });

        ReceiverStream::new(receiver)
    }
}
