# quproxy
A transparent QUIC to SOCKSv5 proxy on Linux,
UDP/QUIC verison of [moproxy](https://github.com/sorz/moproxy).

🚧 WORKING IN PROGRESS 🚧

Features:
- Transparent forward QUIC to upstream SOCKSv5 proxy with iptables/nftables
- Multiple upstream proxy server with availability checking
- Remote DNS resolution (extract domain name from SNI on QUIC handshaking)
- Migrate live connections between upstream proxies
- Full IPv6 support (auto detect)

TODOs:
[] Status page
[] Metrics exporter
[] UDP batch read/write
[] Configure file reload
[] Aggressive retry / try-in-parallel handshaking
