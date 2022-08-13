use parking_lot::Mutex;
use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    sync::{Arc, Weak},
};

use crate::app::{net::AsyncUdpSocket, types::RemoteAddr};

struct WeakGuard<K, V> {
    key: Option<K>,
    value: V,
    bin: Arc<Mutex<Vec<K>>>,
}

impl<K, V> Drop for WeakGuard<K, V> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.bin.lock().push(key);
        }
    }
}

impl<K, V> AsRef<V> for WeakGuard<K, V> {
    fn as_ref(&self) -> &V {
        &self.value
    }
}

impl<K, V> WeakGuard<K, V> {
    fn new(key: K, value: V, bin: Arc<Mutex<Vec<K>>>) -> Self {
        Self {
            key: Some(key),
            value,
            bin,
        }
    }
}

pub(crate) struct TProxySender {
    inner: WeakGuard<RemoteAddr, AsyncUdpSocket>,
}

impl AsRef<AsyncUdpSocket> for TProxySender {
    fn as_ref(&self) -> &AsyncUdpSocket {
        &self.inner.value
    }
}

pub(crate) struct TProxySenderCache {
    senders: HashMap<RemoteAddr, Weak<TProxySender>>,
    bin: Arc<Mutex<Vec<RemoteAddr>>>,
}

impl TProxySenderCache {
    pub(crate) fn new() -> Self {
        Self {
            senders: Default::default(),
            bin: Default::default(),
        }
    }

    pub(crate) fn get_or_create(&mut self, remote: RemoteAddr) -> io::Result<Arc<TProxySender>> {
        // Try to clear up dropped entries
        if let Some(mut bin) = self.bin.try_lock() {
            for key in bin.drain(..) {
                if let Entry::Occupied(entry) = self.senders.entry(key) {
                    if entry.get().upgrade().is_none() {
                        entry.remove_entry();
                    }
                }
            }
        }

        let create_sender = || -> Result<_, io::Error> {
            let sock = AsyncUdpSocket::bind_nonlocal(&remote.0)?;
            let inner = WeakGuard::new(remote, sock, self.bin.clone());
            Ok(Arc::new(TProxySender { inner }))
        };

        match self.senders.entry(remote) {
            Entry::Occupied(mut e) => match e.get().upgrade() {
                Some(v) => Ok(v),
                None => {
                    let sender = create_sender()?;
                    *e.get_mut() = Arc::downgrade(&sender);
                    Ok(sender)
                }
            },
            Entry::Vacant(e) => {
                let sender = create_sender()?;
                e.insert(Arc::downgrade(&sender));
                Ok(sender)
            }
        }
    }
}
