use bytes::Bytes;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::app::types::{ClientAddr, RemoteAddr};

const PKT_CHANNEL_BUF_SIZE: usize = 8;
const SRC_CHANNEL_BUF_SIZE: usize = 4;

pub(crate) type ClientReceiver = Receiver<(ClientAddr, PacketReceiver)>;
pub(crate) type ClientSender = Sender<(ClientAddr, PacketReceiver)>;
pub(crate) type PacketReceiver = Receiver<(RemoteAddr, Bytes)>;
pub(crate) type PacketSender = Sender<(RemoteAddr, Bytes)>;

pub(crate) fn client_channel() -> (ClientSender, ClientReceiver) {
    mpsc::channel(SRC_CHANNEL_BUF_SIZE)
}

pub(crate) fn packet_channel() -> (PacketSender, PacketReceiver) {
    mpsc::channel(PKT_CHANNEL_BUF_SIZE)
}
