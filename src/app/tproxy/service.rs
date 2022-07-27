use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::SocketAddr,
};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use tokio_stream::wrappers::ReceiverStream;

use crate::app::{
    types::{ClientAddr, RemoteAddr},
    AppContext,
};

use super::{
    session::{client_channel, packet_channel, ClientSender, PacketSender},
    socket::AsyncUdpSocket,
};

pub(crate) struct TProxyService<S> {
    context: AppContext<S>,
    tproxy_socket: AsyncUdpSocket,
    packet_senders: HashMap<ClientAddr, PacketSender>,
}

impl<S: Sync + Send + 'static> TProxyService<S> {
    pub(crate) fn new(context: AppContext<S>, bind_addr: &SocketAddr) -> io::Result<Self> {
        let tproxy_socket = AsyncUdpSocket::bind(bind_addr)?;
        Ok(Self {
            context,
            tproxy_socket,
            packet_senders: Default::default(),
        })
    }

    pub(crate) fn launch(
        mut self,
    ) -> impl Stream<Item = (ClientAddr, impl Stream<Item = (RemoteAddr, Bytes)>)> {
        let (sender, receiver) = client_channel();
        tokio::spawn(async move {
            loop {
                self.serve_once(&sender)
                    .await
                    .expect("Error on read TProxy socket");
            }
        });
        ReceiverStream::new(receiver)
            .map(|(client, packets)| (client, ReceiverStream::new(packets)))
    }

    async fn serve_once(&mut self, new_src: &ClientSender) -> io::Result<()> {
        let mut buf = [0u8; 2048];
        let (n, src_addr, dst_addr) = self.tproxy_socket.recv_msg(&mut buf).await?;
        let entry = self.packet_senders.entry(src_addr);
        let sender = match entry {
            Entry::Occupied(ref e) => e.get(),
            Entry::Vacant(e) => {
                // New source
                let (pkt_sender, pkt_receiver) = packet_channel();
                new_src
                    .send((*e.key(), pkt_receiver))
                    .await
                    .expect("send new connection");
                e.insert(pkt_sender)
            }
        };
        let pkt = Bytes::copy_from_slice(&buf[..n]);
        sender
            .send((dst_addr, pkt))
            .await
            .expect("TODO: handle droppred conn");
        Ok(())
    }
}
