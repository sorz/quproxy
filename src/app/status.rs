use std::fmt::Debug;

use parking_lot::Mutex;

use super::{checking::Health, socks5::Usage};

#[derive(Debug, Default)]
pub(crate) struct ServerStatus {
    pub(super) health: Mutex<Health>,
    pub(super) usage: Usage,
}
