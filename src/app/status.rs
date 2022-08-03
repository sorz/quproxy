use std::fmt::Debug;

use parking_lot::Mutex;

use super::{checking::Health, socks5::Usage};

pub(crate) trait Status:
    Send + Sync + Default + Debug + AsRef<Mutex<Health>> + AsRef<Usage> + 'static
{
}

impl Status for ServerStatus {}

#[derive(Debug, Default)]
pub(crate) struct ServerStatus {
    health: Mutex<Health>,
    usage: Usage,
}

impl AsRef<Mutex<Health>> for ServerStatus {
    fn as_ref(&self) -> &Mutex<Health> {
        &self.health
    }
}

impl AsRef<Usage> for ServerStatus {
    fn as_ref(&self) -> &Usage {
        &self.usage
    }
}
