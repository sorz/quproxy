use clap::Parser;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

mod app;
mod cli;

#[tokio::main]
async fn main() {
    let args = cli::CliArgs::parse();
    tracing_subscriber::registry()
        .with(args.log_level)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let context: app::AppContext<app::ServerStatus> = app::AppContext::from_cli_args(&args);
    let checking_service =
        app::CheckingService::new(context.clone(), args.check_interval, args.check_dns_server);
    let referrer_service =
        app::SocksReferService::new(context.clone(), args.socks5_tcp_check_interval);
    let tproxy_addr = (args.host, args.port).into();
    let tproxy_service = app::TProxyService::new(context.clone(), &tproxy_addr)
        .expect("Failed to launch TProxy service");
    let forward_service = app::SocksForwardService::new(context.clone());

    tokio::spawn(referrer_service.launch());
    tokio::spawn(checking_service.launch());

    let incoming_clients = tproxy_service.launch();
    forward_service.serve(incoming_clients).await;
}
