use std::{net::SocketAddr, sync::Arc};

use shadowsocks::{
    context::Context, relay::tcprelay::utils::copy_encrypted_bidirectional, ProxyClientStream, ServerConfig,
};
use tokio::net::TcpStream;
use tracing::{error, info};

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
        connect_opts.tcp.mptcp = true;
        connect_opts.tcp.fastopen = true;

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
        
        match copy_encrypted_bidirectional(svr_cfg.method(),  &mut remote,&mut stream ).await {
            Ok(_) => {
                info!("{} <-> {} closed", src, target);
            }
            Err(err) => {
                error!("{} <-> {} closed with error: {}", src, target, err);
            }
        }
    }
}
