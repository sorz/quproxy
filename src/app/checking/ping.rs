use std::{
    cmp,
    collections::{HashSet, VecDeque},
    fmt::Display,
    io,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    num::NonZeroU8,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use futures::StreamExt;
use hex_literal::hex;
use tokio::time::{interval_at, timeout};
use tracing::{debug, instrument, trace, warn};

use crate::app::{net::MsgArrayWriteBuffer, socks5::SocksServer, InnerProto};

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

    /// Assume exponential distribution for round-trip time (RTT):
    /// RTT = base + D, where D ~ Exp(λ), base is a constant over observation.
    ///
    /// This method is a inverse distribution function over the RTT
    /// distribution fitted by observed pings.  
    pub(crate) fn quantile_delay(&self, quantile: f32) -> Option<Duration> {
        assert!(quantile > 0f32 && quantile < 1f32);
        let pings: Vec<_> = self
            .pings
            .iter()
            .copied()
            .flatten()
            .map(|t| t.as_millis() as f32)
            .collect();
        if pings.len() < 3 {
            return None;
        }
        let exp = mean(&pings);
        let var = variance(&pings, exp);
        // Var[D] = 1/λ^2, Var[D] = Var[RTT]
        //   => λ = sqrt(1/Var[RTT])
        // base = E[RTT] - E[D] = E[RTT] - 1/λ
        let λ = (1f32 / var).sqrt();
        let base = (exp - (1.0 / λ)).clamp(5.0, f32::MAX);
        // Inverse CDF: -ln(1-p)/λ
        let millis = -(1.0 - quantile).ln() / λ;
        Some(Duration::from_secs_f32((base + millis) / 1000.0))
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

fn mean(xs: &[f32]) -> f32 {
    xs.iter().fold(0f32, |acc, elem| acc + *elem) / xs.len() as f32
}

fn variance(xs: &[f32], xbar: f32) -> f32 {
    let sum = xs
        .iter()
        .copied()
        .map(|x| (x - xbar) * (x - xbar))
        .fold(0f32, |acc, elem| acc + elem);
    sum / (xs.len() as f32 - 1.0)
}

#[async_trait]
pub(super) trait Pingable {
    async fn ping_with_dns_query(
        &self,
        dns_addr: SocketAddr,
        count: usize,
    ) -> io::Result<Option<Duration>>;

    async fn probe_inner_proto(&self, dns4: SocketAddrV4, dns6: SocketAddrV6) -> InnerProto;
}

const DNS_QUERY: &[u8] = &hex!(
    // Omit 2-byte transcation ID
    // Flags: do recursive query, AD
    "0120"
    // # of question/answer/authority/addition
    "0001 0000 0000 0001"
    // Name: google.com
    "06 676f6f676c6503636f6d 00"
    // TXT IN
    "0010 0001"
    // EDNS0: 1200B UDP payload
    "00 0029 04b0 00000000"
    // Omit 2-byte RDATA length
);

const DNS_QUERY_SIZE: usize = 500;

#[async_trait]
impl Pingable for Arc<SocksServer> {
    #[instrument(skip_all, fields(server=self.name, dns=?dns_addr))]
    async fn ping_with_dns_query(
        &self,
        dns_addr: SocketAddr,
        count: usize,
    ) -> io::Result<Option<Duration>> {
        // Generate unique transcation IDs
        let tids: Vec<_> = {
            let mut set: HashSet<u16> = HashSet::with_capacity(count);
            while set.len() < count {
                set.insert(rand::random());
            }
            set.into_iter().collect()
        };

        let (wait_send, wait_last) = {
            let pings = self.status.pings.lock();
            match (pings.quantile_delay(0.8), pings.quantile_delay(0.95)) {
                (Some(a), Some(b)) => (a, cmp::max(b, Duration::from_millis(500))),
                _ => (Duration::from_millis(200), Duration::from_millis(2000)),
            }
        };
        trace!("wait_send {:#.1?}, wait_last {:#.1?}", wait_send, wait_last);

        let session: Arc<_> = self.bind(dns_addr.into()).await?.into();

        // Send queries
        let tid_send = tids.clone();
        let session_clone = session.clone();
        let mut send_inverval = interval_at(Instant::now().into(), wait_send);
        let task_send = async move {
            let mut buf = MsgArrayWriteBuffer::with_capacity(1);
            for tid in tid_send {
                send_inverval.tick().await;
                // Construct DNS query
                let mut query = BytesMut::with_capacity(DNS_QUERY_SIZE);
                query.put_u16(tid);
                query.put_slice(DNS_QUERY);
                // Fill query to match DNS_QUERY_SIZE size
                let rdata_len: u16 = (DNS_QUERY_SIZE - query.len() - 2).try_into().unwrap();
                query.put_u16(rdata_len); // RDATA length
                query.put_u16(65001); // Option code: local/experimental use
                query.put_u16(rdata_len - 4); // Option length
                query.put_bytes(rand::random(), (rdata_len - 4) as usize);
                assert!(query.len() == DNS_QUERY_SIZE);
                trace!("Send DNS query: {:?}", query);
                session_clone
                    .send_to_remote(&[query.freeze()], &mut buf)
                    .await?;
            }
            Ok(())
        };

        // Receive replies
        let mut incoming = Box::pin(session.incoming());
        let task_recv = async move {
            let t0 = Instant::now();
            timeout(wait_send * (count as u32 - 1) + wait_last, async {
                loop {
                    let pkts = match incoming.next().await.unwrap() {
                        Ok(pkts) => pkts,
                        Err(err) => break Err(err),
                    };
                    for pkt in pkts.iter() {
                        if pkt.len() < 12 {
                            debug!("DNS reply too short ({} bytes)", pkt.len());
                            continue;
                        }
                        if pkt.len() < 400 {
                            warn!("Suspicious DNS reply: {} < 400 bytes", pkt.len())
                        }
                        trace!("Recevied DNS reply: {:?}", &pkt);
                        let tid = (pkt[0] as u16) << 8 | (pkt[1] as u16);
                        if let Some(n) = tids.iter().position(|t| t == &tid) {
                            let delay = t0.elapsed() - wait_send * (n as u32);
                            return Ok((n, delay));
                        } else {
                            debug!("Unknown transcation ID ({})", tid);
                            continue;
                        }
                    }
                }
            })
            .await
        };

        let (loss, delay) = tokio::select! {
            Err(err) = task_send => return Err(err),
            result = task_recv => match result {
                Ok(Err(err)) => return Err(err),
                Ok(Ok((loss, delay))) => {
                    trace!("[{}] Ping: {:#.1?}, lost {}", self.name, delay, loss);
                    (loss, Some(delay))
                },
                Err(_) => {
                    trace!("[{}] Ping: {}/{} lost", self.name, count, count);
                    (count - 1, None)
                }
            },
        };
        let mut pings = self.status.pings.lock();
        (0..loss).for_each(|_| pings.add_measurement(None));
        pings.add_measurement(delay.map(Delay::from));
        Ok(delay)
    }

    #[instrument(skip_all, fields(server=self.name))]
    async fn probe_inner_proto(&self, dns4: SocketAddrV4, dns6: SocketAddrV6) -> InnerProto {
        // False rate = p^N * (1-p)^N, where p = (packet loss rate)^R
        // Fail rate = TODO
        const N: usize = 3; // Max false rate (when p = 0.5) is 0.5^(3 * 2) = 1.6%
        const R: usize = 3;
        let mut v4_ok_cnt = 0usize;
        let mut v6_ok_cnt = 0usize;
        let mut test_cnt = 0usize;
        for _ in 0..N {
            test_cnt += 1;
            tokio::select! {
                Ok(_) = self.ping_with_dns_query(dns4.into(), R) => v4_ok_cnt += 1,
                Ok(_) = self.ping_with_dns_query(dns6.into(), R) => v6_ok_cnt += 1,
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
