use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use clap::Parser;
use tracing::metadata::LevelFilter;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub(crate) struct CliArgs {
    /// Address to bind on for the incoming UDP sessions
    #[clap(short = 'h', long)]
    #[clap(default_value_t = Ipv6Addr::UNSPECIFIED.into())]
    pub(crate) host: IpAddr,

    /// Port number to bind on for the incoming UDP sessions
    #[clap(short = 'p', long, required = true)]
    pub(crate) port: u16,

    /// TCP socket address of SOCKSv5 servers. The UDP socket addresses will
    /// be retrived via long-live TCP connections. This conforms to RFC 1928.
    #[clap(short = 't', long)]
    #[clap(multiple_values = true)]
    pub(crate) socks5_tcp: Vec<SocketAddr>,

    /// UDP socket address of SOCKSv5 servers. No bother to make TCP
    /// connection to SOCKS server. Sutiable for popular proxy suites like
    /// Shadowsocks-Rust and V2ray.
    #[clap(short = 'u', long)]
    #[clap(multiple_values = true)]
    pub(crate) socks5_udp: Vec<SocketAddr>,

    /// Period of time to make one availability check  
    #[clap(long, default_value = "30s")]
    #[clap(parse(try_from_str = parse_duration::parse))]
    pub(crate) check_interval: Duration,

    /// Address of a DNS server to do availability check
    #[clap(long, default_value = "1.1.1.1:53")]
    pub(crate) check_dns_server: SocketAddr,

    /// Period of time to check & reinitiate SOCKSv5 TCP connections
    #[clap(long, default_value = "20s")]
    #[clap(parse(try_from_str = parse_duration::parse))]
    pub(crate) socks5_tcp_check_interval: Duration,

    /// Level of logging verbosity [possible values: off, error, warn, info,
    /// debug, trace]
    #[clap(long)]
    #[clap(default_value = "info")]
    pub(crate) log_level: LevelFilter,
}
