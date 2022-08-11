mod socket;

pub(crate) const UDP_MAX_SIZE: usize = 2048;
pub(crate) const UDP_BATCH_SIZE: usize = 16;

pub(crate) use socket::{AsyncUdpSocket, Message, MsgArrayReadBuffer};
