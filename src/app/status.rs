use parking_lot::Mutex;

use super::checking::Health;

#[derive(Debug, Default)]
pub(crate) struct ServerStatus {
    health: Mutex<Health>,
}

impl AsRef<Mutex<Health>> for ServerStatus {
    fn as_ref(&self) -> &Mutex<Health> {
        &self.health
    }
}
