use std::{net::SocketAddr, sync::Arc};

use shadowsocks::{
    context::Context, relay::tcprelay::utils::copy_bidirectional, ProxyClientStream,
    ServerConfig,
};
use tokio::net::TcpStream;
use tracing::{error, trace};

use super::Proxy;

impl Proxy {
    pub async fn handle_tcp_stream(
        &self,
        src: SocketAddr,
        mut stream: TcpStream,
        svr_cfg: ServerConfig,
        context: Arc<Context>,
    ) {
        let loopback = match stream.local_addr() {
            Ok(local_addr) => local_addr.ip(),
            Err(e) => {
                error!("[Get LoopBack] failed: {}", e);
                return;
            }
        };
        let target = self.get_projection(loopback).await;
        let mut parts = target.rsplitn(2, ':');
        let port_str = match parts.next().ok_or("Missing port number") {
            Ok(port_str) => port_str,
            Err(e) => {
                error!("[Get Port] failed: {}", e);
                return;
            }
        };
        let port: u16 = match port_str.parse() {
            Ok(port) => port,
            Err(e) => {
                error!("[Parse Port] failed: {}", e);
                return;
            }
        };
        let host = match parts.next().ok_or("Missing host") {
            Ok(host) => host.to_string(),
            Err(e) => {
                error!("[Get Host] failed: {}", e);
                return;
            }
        };
        let target_addr = (host, port);

        let mut connect_opts = shadowsocks::net::ConnectOpts::default();
        connect_opts.tcp.nodelay = true;

        let mut remote = match ProxyClientStream::connect_with_opts(
            context,
            &svr_cfg,
            target_addr,
            &connect_opts,
        )
        .await
        {
            Ok(stream) => stream,
            Err(e) => {
                error!("connect to target failed: {}", e);
                return;
            }
        };

        match copy_bidirectional(&mut remote, &mut stream).await {
            Ok(_) => {
                trace!("{} <-> {} closed", src, target);
            }
            Err(err) => {
                trace!("{} <-> {} closed with error: {}", src, target, err);
            }
        }
    }
}
