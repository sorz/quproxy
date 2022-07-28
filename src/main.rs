use clap::Parser;
use tracing_subscriber::prelude::*;

mod app;
mod cli;

#[tokio::main]
async fn main() {
    let args = cli::CliArgs::parse();
    tracing_subscriber::registry()
        .with(args.log_level)
        .with(tracing_subscriber::fmt::layer())
        .init();
    let context: app::AppContext<app::ServerStatus> = app::AppContext::from_cli_args(args);

    let checking_service = app::CheckingService::new(context.clone());
    let referrer_service = app::SocksReferService::new(context.clone());
    tokio::spawn(referrer_service.launch());
    tokio::spawn(checking_service.launch());

    let tproxy_receiver =
        app::TProxyReceiver::new(context.clone()).expect("Failed to launch TProxy receiver");
    let tproxy_sender = app::TProxySender::new(context.clone());
    let receiver = tproxy_receiver.incoming_packets();
    let sender = tproxy_sender.launch();

    app::SocksForwardService::new(context.clone(), sender)
        .serve(receiver)
        .await;
}
