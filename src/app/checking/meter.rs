use std::{collections::VecDeque, time::Instant};

use crate::app::socks5::{SocksServer, Traffic};

use super::Healthy;

const MAX_SAMPLES: usize = 5;

#[derive(Debug)]
pub(crate) struct Meter {
    samples: VecDeque<Sample>,
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    _time: Instant,
    traffic: Traffic,
}

impl From<Traffic> for Sample {
    fn from(traffic: Traffic) -> Self {
        Self {
            _time: Instant::now(),
            traffic,
        }
    }
}

impl Default for Meter {
    fn default() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_SAMPLES),
        }
    }
}

impl Meter {
    fn add_sample(&mut self, traffic: Traffic) {
        while self.samples.len() >= MAX_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(traffic.into());
    }

    /// Return true if there is TX traffic but no RX traffic, excpet all TX
    /// occur only in the latter half samples.
    pub(super) fn tx_only(&self) -> bool {
        let x = self.samples.front().copied();
        let a = self.samples.get(MAX_SAMPLES / 2).copied();
        let b = self.samples.get(MAX_SAMPLES - 1).copied();
        if let (Some(x), Some(a), Some(b)) = (x, a, b) {
            let head = a.traffic - x.traffic;
            let total = b.traffic - x.traffic;
            head.tx_bytes > 0 && total.rx_bytes == 0
        } else {
            false
        }
    }
}

pub(super) trait Sampling {
    fn sample_traffic(&self);
}

impl Sampling for SocksServer {
    fn sample_traffic(&self) {
        let mut meter = self.status.meter.lock();
        let sample = self.status.usage.traffic.get();
        meter.add_sample(sample);
        if sample.rx_bytes > 0 {
            // Fast recovery from trouble
            self.set_troubleness(false);
        }
    }
}
