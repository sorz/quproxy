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
    let context = app::AppContext::from_cli_args(args);

    tokio::spawn(app::SocksReferService::new(&context).launch());
    if !context.cli_args.no_check {
        tokio::spawn(app::CheckingService::new(&context).launch());
    }

    let tproxy_receiver =
        app::TProxyReceiver::new(&context).expect("Failed to launch TProxy receiver");
    let tproxy_sender = app::TProxySender::new(&context);
    let receiver = tproxy_receiver.incoming_packets();
    let sender = tproxy_sender.launch();

    app::SocksForwardService::new(&context, sender)
        .serve(receiver)
        .await;
}
