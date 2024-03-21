use clap::{arg, command, value_parser, Arg, ArgAction};
use tracer::Tracer;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, EnvFilter, FmtSubscriber};

mod proxy;
mod tracer;

#[tokio::main]
async fn main() {
    let matches = command!()
        .arg(
            Arg::new("debug")
                .short('v') 
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
                .help("Activate debug mode"),
        )
        .arg(
            Arg::new("proxy_port")
                .short('p')
                .value_parser(value_parser!(usize))
                .long("proxy_port")
                .action(ArgAction::Set)
                .required(true)
                .help("The proxy server port"),
        )
        .arg(arg!([COMMAND] ... "Command and arguments to run through the proxy").trailing_var_arg(true))
        .get_matches();

    let debug = matches.get_flag("debug");
    let socks5_port: usize = *matches
        .get_one("proxy_port")
        .expect("`proxy_port` is required");
    let commands: Vec<&String> = matches
        .get_many::<String>("COMMAND")
        .expect("`COMMAND`is required")
        .collect();
    let program_name = commands[0];
    let program_args: Vec<&str> = commands[1..].iter().map(AsRef::as_ref).collect();

    let mut log_level = LevelFilter::WARN;
    if debug {
        log_level = LevelFilter::TRACE;
    }
    let filter = EnvFilter::builder()
        .with_default_directive(log_level.into())
        .from_env_lossy()
        .add_directive("hickory_proto=off".parse().unwrap());
    let (writer, _) = tracing_appender::non_blocking(std::io::stdout());
    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .event_format(fmt::format().compact());
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_env_filter(filter)
        .with_writer(writer)
        .finish()
        .with(fmt_layer);
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set default subscriber");
    let tracer: Tracer = Tracer::new(program_name, program_args, socks5_port);
    let recv = tracer.proxy.clone().listen_and_serve(0).await;
    recv.await.unwrap();
    tracer.trace().await;
}

