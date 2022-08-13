macro_rules! io_error {
    ($kind:ident, $msg:expr) => {
        return Err(io::Error::new(io::ErrorKind::$kind, $msg))
    };
    ($msg:expr) => {
        io_error!(Other, $msg)
    };
}

mod checking;
mod context;
mod net;
mod quic;
mod socks5;
mod status;
mod tproxy;
pub(crate) mod types;

pub(crate) use checking::CheckingService;
pub(crate) use context::AppContext;
pub(crate) use socks5::{InnerProto, SocksForwardService, SocksReferService};
pub(crate) use status::ServerStatus;
pub(crate) use tproxy::TProxyReceiver;
