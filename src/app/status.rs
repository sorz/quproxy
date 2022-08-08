use std::fmt::Debug;

use parking_lot::Mutex;

use super::{
    checking::{Meter, PingHistory},
    socks5::Usage,
};

#[derive(Debug, Default)]
pub(crate) struct ServerStatus {
    pub(super) pings: Mutex<PingHistory>,
    pub(super) usage: Usage,
    pub(super) meter: Meter,
}
