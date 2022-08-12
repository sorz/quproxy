use std::{collections::HashMap, io, pin::Pin};

use bytes::Bytes;
use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, trace};

use crate::app::{
    net::{AsyncUdpSocket, MsgArrayReadBuffer, UDP_BATCH_SIZE, UDP_MAX_SIZE},
    types::UdpPackets,
    AppContext,
};

pub(crate) struct TProxyReceiver {
    _context: AppContext,
    tproxy_socket: AsyncUdpSocket,
}

impl TProxyReceiver {
    pub(crate) fn new(context: &AppContext) -> io::Result<Self> {
        let bind_addr = (context.cli_args.host, context.cli_args.port).into();
        let tproxy_socket = AsyncUdpSocket::bind_tproxy(&bind_addr)?;
        Ok(Self {
            _context: context.clone(),
            tproxy_socket,
        })
    }

    pub(crate) fn incoming_packets(self) -> impl Stream<Item = UdpPackets> {
        let (sender, receiver) = mpsc::channel::<UdpPackets>(16);
        tokio::spawn(async move {
            let mut buf: Pin<Box<MsgArrayReadBuffer<UDP_BATCH_SIZE, UDP_MAX_SIZE>>> =
                MsgArrayReadBuffer::new();
            loop {
                buf.clear();
                self.tproxy_socket
                    .batch_recv(&mut buf)
                    .await
                    .expect("Error on read TProxy socket");
                if buf.len() >= UDP_BATCH_SIZE / 2 {
                    // FIXME: remove it
                    info!(
                        "TProxy batch recv {}/{} messages",
                        buf.len(),
                        UDP_BATCH_SIZE
                    );
                }
                let mut addrs_pkts: HashMap<_, Vec<_>> = HashMap::new();
                buf.iter()
                    .inspect(|msg| trace!("Receive from TProxy: {}", msg))
                    .filter_map(|msg| Some(((msg.src_addr?, msg.dst_addr?), msg.buf)))
                    .for_each(|(addrs, pkt)| {
                        addrs_pkts
                            .entry(addrs)
                            .or_default()
                            .push(Bytes::copy_from_slice(pkt))
                    });
                for ((src, dst), pkts) in addrs_pkts.into_iter() {
                    sender
                        .send((src.into(), dst.into(), pkts.into_boxed_slice()))
                        .await
                        .expect("Error on send incoming packet");
                }
            }
        });

        ReceiverStream::new(receiver)
    }
}
