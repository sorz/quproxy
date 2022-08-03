use std::fmt::Debug;

use parking_lot::Mutex;

use super::checking::Health;

pub(crate) trait Status:
    Send + Sync + AsRef<Mutex<Health>> + Default + Debug + 'static
{
}

impl Status for ServerStatus {}

#[derive(Debug, Default)]
pub(crate) struct ServerStatus {
    health: Mutex<Health>,
}

impl AsRef<Mutex<Health>> for ServerStatus {
    fn as_ref(&self) -> &Mutex<Health> {
        &self.health
    }
}
