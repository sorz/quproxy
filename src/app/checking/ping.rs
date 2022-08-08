use std::{
    collections::VecDeque,
    fmt::Display,
    io,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    num::NonZeroU8,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::time::timeout;
use tracing::{debug, instrument, trace};

use crate::app::{
    socks5::{Bindable, SocksServer},
    InnerProto,
};

const DELAY_POWER: f32 = 0.75;
const DELAY_MAX_HISTORY: usize = 100;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Delay(NonZeroU8);

impl From<Duration> for Delay {
    fn from(t: Duration) -> Self {
        let v = (t.as_millis() as f32).powf(DELAY_POWER).round() as u8;
        Self(v.try_into().unwrap_or_else(|_| 1.try_into().unwrap()))
    }
}

impl From<Delay> for Duration {
    fn from(d: Delay) -> Self {
        Duration::from_millis(d.as_millis() as u64)
    }
}

impl Delay {
    pub(crate) fn as_millis(&self) -> u16 {
        (self.0.get() as f32).powf(1.0 / DELAY_POWER) as u16
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PingHistory {
    pings: VecDeque<Option<Delay>>,
}

impl Default for PingHistory {
    fn default() -> Self {
        Self {
            pings: VecDeque::with_capacity(DELAY_MAX_HISTORY),
        }
    }
}

impl Display for PingHistory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(delay) = self.average_delay() {
            write!(
                f,
                "[{:#.1?} {}% {}]",
                delay,
                self.loss_percent(),
                self.score()
            )
        } else {
            write!(f, "[unknown ({})]", self.score())
        }
    }
}

impl PingHistory {
    pub(super) fn add_measurement(&mut self, delay: Option<Delay>) {
        if self.pings.len() >= DELAY_MAX_HISTORY {
            self.pings.pop_front();
        }
        self.pings.push_back(delay);
    }

    pub(crate) fn loss_percent(&self) -> u8 {
        let lost = self.pings.iter().copied().filter(Option::is_none).count();
        ((lost as f32) / (self.pings.len() as f32) * 100.0).round() as u8
    }

    pub(crate) fn average_delay(&self) -> Option<Duration> {
        let (count, sum) =
            self.pings
                .iter()
                .copied()
                .fold((0usize, 0u32), |(count, sum), x| match x {
                    Some(delay) => (count + 1, sum + delay.as_millis() as u32),
                    None => (count, sum),
                });
        if count == 0 {
            None
        } else {
            Duration::from_millis(sum as u64 / count as u64).into()
        }
    }

    pub(super) fn score(&self) -> i16 {
        if let Some(delay) = self.average_delay() {
            let delay_ms = delay.as_millis().clamp(10, 2000) as f32;
            let loss_rate = self.loss_percent().clamp(0, 99) as f32 / 100.0;
            let score = (delay_ms + loss_rate * 1000.0) / (1.0 - loss_rate).powf(2.0);
            score.clamp(i16::MIN as f32, i16::MAX as f32).round() as i16
        } else {
            i16::MAX
        }
    }
}

#[async_trait]
pub(super) trait Pingable: Bindable {
    #[instrument(skip_all, fields(server=self.server_name(), dns=?dns_addr))]
    async fn ping_with_dns_query(
        &self,
        dns_addr: SocketAddr,
        max_wait: Duration,
    ) -> io::Result<Duration> {
        trace!("Checking DNS query delay");
        // Construct DNS query for A record of "." (root)
        let query: [u8; 17] = [
            rand::random(),
            rand::random(), // transcation ID
            1,
            32, // standard query
            0,
            1, // one query
            0,
            0, // zero answer
            0,
            0, // zero authority
            0,
            0, // zero addition
            0, // query: root
            0,
            1, // query: type A
            0,
            1, // query: class IN
        ];
        let parse_tid = |req: &[u8]| (req[0] as u16) << 8 | (req[1] as u16);
        let query_tid = parse_tid(&query);

        // Send query & receive reply
        let t0 = Instant::now();
        let mut buf = [0u8; 12];
        let n = timeout(max_wait, async {
            let proxy = self.bind(None).await?;
            trace!("Send DNS query: {:?}", query);
            proxy.send_to_remote(dns_addr.into(), &query).await?;
            proxy.recv(&mut buf).await
        })
        .await??;

        // Validate reply
        if n < 12 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "DNS reply too short",
            ));
        }
        trace!("Recevied DNS reply (truncated): {:?}", &buf[..n]);
        if query_tid != parse_tid(&buf[..n]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "broken DNS reply received",
            ));
        }
        Ok(t0.elapsed())
    }

    #[instrument(skip_all, fields(server=self.server_name()))]
    async fn probe_inner_proto(
        &self,
        dns4: SocketAddrV4,
        dns6: SocketAddrV6,
        rtt: Duration,
    ) -> InnerProto {
        // False rate = p^N * (1-p)^N, where p is packet loss rate
        const N: usize = 3; // Max false rate (when p = 0.5) is 0.5^(3 * 2) = 1.6%
        let max_wait = rtt * 2;
        let mut v4_ok_cnt = 0usize;
        let mut v6_ok_cnt = 0usize;
        let mut test_cnt = 0usize;
        for _ in 0..N {
            test_cnt += 1;
            tokio::select! {
                Ok(_) = self.ping_with_dns_query(dns4.into(), max_wait) => v4_ok_cnt += 1,
                Ok(_) = self.ping_with_dns_query(dns6.into(), max_wait) => v6_ok_cnt += 1,
                else => (),
            }
            if v4_ok_cnt > 0 && v6_ok_cnt > 0 {
                break;
            }
        }
        debug!(
            "v4 {}/{}, v6 {}/{}",
            v4_ok_cnt, test_cnt, v6_ok_cnt, test_cnt
        );
        match (v4_ok_cnt, v6_ok_cnt) {
            (N, 0) => InnerProto::IPv4,
            (0, N) => InnerProto::IPv6,
            (0, 0) => InnerProto::Unspecified,
            (_, _) => InnerProto::Inet,
        }
    }
}

impl Pingable for Arc<SocksServer> {}
