use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    path::{Path, PathBuf},
    time::Duration,
};

use clap::Parser;
use serde::Deserialize;
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

    /// TOML config file with the list of upstream proxy servers.
    #[clap(short = 'l', long)]
    pub(crate) list: Option<PathBuf>,

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

    /// Obtain domain name from QUIC initial packet (if exists), pass it to
    /// SOCKSv5 server for remote DNS resolution.
    #[clap(long)]
    pub(crate) remote_dns: bool,

    /// Disable availability check
    #[clap(long)]
    pub(crate) no_check: bool,

    /// Period of time to make one availability check  
    #[clap(long, default_value = "30s")]
    #[clap(parse(try_from_str = parse_duration::parse))]
    pub(crate) check_interval: Duration,

    /// Address of a DNS server to do availability check (IPv4)
    #[clap(long, default_value = "1.1.1.1:53")]
    pub(crate) check_dns_server_v4: SocketAddrV4,

    /// Address of a DNS server to do availability check (IPv6)
    #[clap(long, default_value = "[2606:4700:4700::1111]:53")]
    pub(crate) check_dns_server_v6: SocketAddrV6,

    /// Period of time to check & reinitiate SOCKSv5 TCP connections
    #[clap(long, default_value = "20s")]
    #[clap(parse(try_from_str = parse_duration::parse))]
    pub(crate) socks5_tcp_check_interval: Duration,

    /// Level of logging verbosity [possible values: off, error, warn, info,
    /// debug, trace]
    #[clap(long)]
    #[clap(default_value = "info")]
    pub(crate) log_level: LevelFilter,

    /// Max idle time before stop tracking a UDP session
    #[clap(long, default_value = "90s")]
    #[clap(parse(try_from_str = parse_duration::parse))]
    pub(crate) udp_session_timeout: Duration,

    /// Max number of tracked UDP sessions
    #[clap(long, default_value_t = 512)]
    pub(crate) udp_max_sessions: usize,
}

#[derive(Deserialize, Default)]
pub(crate) struct ConfigFile {
    #[serde(serialize_with = "toml::ser::tables_last")]
    pub(crate) upstreams: HashMap<String, Upstream>,
}

#[derive(Deserialize, Default, PartialEq, Eq, Clone, Copy)]
pub(crate) enum UpstreamProtocol {
    #[default]
    #[serde(alias = "socks5udp")]
    #[serde(alias = "socks5_udp")]
    Socks5Udp,
    #[serde(alias = "socks5tcp")]
    #[serde(alias = "socks5_tcp")]
    Socks5Tcp,
}

fn bool_true() -> bool {
    true
}

#[derive(Deserialize, PartialEq, Eq)]
pub(crate) struct Upstream {
    #[serde(alias = "proto")]
    #[serde(default)]
    pub(crate) protocol: UpstreamProtocol,
    #[serde(alias = "addr")]
    pub(crate) address: SocketAddr,
    #[serde(default = "bool_true")]
    pub(crate) enabled: bool,
}

impl ConfigFile {
    pub(crate) fn from_path<T: AsRef<Path>>(path: T) -> io::Result<Self> {
        let mut buf = String::new();
        File::open(path)?.read_to_string(&mut buf)?;
        Ok(toml::de::from_str(&buf)?)
    }
}
