use std::fmt::Debug;

use parking_lot::Mutex;

use super::{
    checking::{Health, Meter, PingHistory},
    socks5::Usage,
};

#[derive(Debug, Default)]
pub(crate) struct ServerStatus {
    pub(super) pings: Mutex<PingHistory>,
    pub(super) usage: Usage,
    pub(super) meter: Mutex<Meter>,
    pub(super) health: Health,
}
