use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::SocketAddr,
};

use bytes::Bytes;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::app::AppContext;

use super::{
    connection::{ConnSocketPair, UdpConnection},
    socket::AsyncUdpSocket,
};

const CONN_QUEUE_BUF: usize = 8;

pub(crate) struct TProxyService<S> {
    context: AppContext<S>,
    tproxy_socket: AsyncUdpSocket,
    alive_conns: HashMap<ConnSocketPair, Sender<Bytes>>,
}

impl<S: Sync + Send + 'static> TProxyService<S> {
    pub(crate) fn new(context: AppContext<S>, bind_addr: &SocketAddr) -> io::Result<Self> {
        let tproxy_socket = AsyncUdpSocket::bind(bind_addr)?;
        Ok(Self {
            context,
            tproxy_socket,
            alive_conns: Default::default(),
        })
    }

    pub(crate) fn launch(mut self) -> Receiver<UdpConnection> {
        let (conn_sender, conn_receiver) = mpsc::channel(CONN_QUEUE_BUF);
        tokio::spawn(async move {
            loop {
                self.serve_once(&conn_sender)
                    .await
                    .expect("Error on read TProxy socket");
            }
        });
        conn_receiver
    }

    async fn serve_once(&mut self, new_conn: &Sender<UdpConnection>) -> io::Result<()> {
        let mut buf = [0u8; 2048];
        let (n, socket_pair) = self.tproxy_socket.recv_msg(&mut buf).await?;
        let entry = self.alive_conns.entry(socket_pair);
        let sender = match entry {
            Entry::Occupied(ref e) => e.get(),
            Entry::Vacant(e) => {
                // New connection
                let (conn, sender) = UdpConnection::new(*e.key());
                new_conn.send(conn).await.expect("send new connection");
                e.insert(sender)
            }
        };
        let pkt = Bytes::copy_from_slice(&buf[..n]);
        sender.send(pkt).await.expect("TODO: handle droppred conn");
        Ok(())
    }
}
