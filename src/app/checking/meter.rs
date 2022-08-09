use std::{collections::VecDeque, time::Instant};

use crate::app::socks5::{SocksServer, Traffic};

use super::Healthy;

const MAX_SAMPLES: usize = 3;

#[derive(Debug)]
pub(crate) struct Meter {
    samples: VecDeque<Sample>,
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    time: Instant,
    traffic: Traffic,
}

impl From<Traffic> for Sample {
    fn from(traffic: Traffic) -> Self {
        Self {
            time: Instant::now(),
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

    fn tx_only(&self) -> bool {
        if self.samples.len() < MAX_SAMPLES {
            return false;
        }
        let first = *self.samples.front().unwrap();
        let last = *self.samples.back().unwrap();
        let amt = last.traffic - first.traffic;
        amt.tx_bytes > 0 && amt.rx_bytes == 0
    }
}

pub(super) trait Sampling {
    fn sample_traffic(&self) -> bool;
}

impl Sampling for SocksServer {
    fn sample_traffic(&self) -> bool {
        let mut meter = self.status.meter.lock();
        let sample = self.status.usage.traffic.get();
        meter.add_sample(sample);
        if sample.rx_bytes > 0 {
            // Fast recovery from trouble
            self.set_troubleness(false);
        }
        meter.tx_only()
    }
}
