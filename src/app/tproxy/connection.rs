use std::net::SocketAddr;

use bytes::Bytes;
use futures::Stream;
use tokio::sync::mpsc::{self, Receiver, Sender};

const CHANNEL_BUF_SIZE: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ConnSocketPair {
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
}

impl From<(SocketAddr, SocketAddr)> for ConnSocketPair {
    fn from((src, dst): (SocketAddr, SocketAddr)) -> Self {
        Self { src, dst }
    }
}
#[derive(Debug)]
pub(crate) struct UdpConnection {
    pub(crate) socket_pair: ConnSocketPair,
    receiver: Receiver<Bytes>,
}

impl UdpConnection {
    pub(crate) fn new(socket_pair: ConnSocketPair) -> (Self, Sender<Bytes>) {
        let (sender, receiver) = mpsc::channel(CHANNEL_BUF_SIZE);
        (
            Self {
                socket_pair,
                receiver,
            },
            sender,
        )
    }
}

impl Stream for UdpConnection {
    type Item = Bytes;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}
