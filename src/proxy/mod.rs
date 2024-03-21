use self::{ip_mapper::Mapper, real_ip_mapper::RealIPMapper};
use shadowsocks::{config::ServerType, context::Context, crypto::CipherKind, relay::Address, ServerConfig};
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{oneshot, Mutex, OnceCell},
};
use tracing::{error, info};

mod ip_mapper;
mod real_ip_mapper;
mod tcp;
mod udp;

pub struct Proxy {
    mapper: Mutex<Mapper>,
    real_ip_mapper: RealIPMapper,
    tcp_listener: OnceCell<Arc<TcpListener>>,
    udp_listener: OnceCell<Arc<UdpSocket>>,
    tcp_port: AtomicU16,
    udp_port: AtomicU16,
    socks5_server_port: usize,
}

pub trait IPMapper {
    fn alloc(&mut self, target: String) -> IpAddr;
    fn get(&self, loopback: IpAddr) -> String;
}

impl Proxy {
    pub fn new(socks5_server_port: usize) -> Self {
        let real_ip_mapper = RealIPMapper::new();
        Proxy {
            mapper: Mutex::new(Mapper::new()),
            real_ip_mapper,
            tcp_listener: OnceCell::new(),
            udp_listener: OnceCell::new(),
            tcp_port: AtomicU16::new(0),
            udp_port: AtomicU16::new(0),
            socks5_server_port,
        }
    }

    pub async fn alloc_projection(&self, target: String) -> IpAddr {
        let mut map = self.mapper.lock().await;
        let ip = if target.contains(":") {
            map.addr_mapper.alloc(target)
        } else {
            map.domain_mapper.alloc(target)
        };
        ip
    }

    pub async fn get_projection(&self, loopback: IpAddr) -> String {
        let map = self.mapper.lock().await;
        let loopback = match loopback {
            IpAddr::V4(_) => loopback,
            IpAddr::V6(addr) => {
                if let Some(ipv4_addr) = addr.to_ipv4_mapped() {
                    IpAddr::V4(ipv4_addr)
                } else {
                    IpAddr::V6(addr)
                }
            }
        };
        let target = if loopback.is_loopback() {
            map.addr_mapper.get(loopback)
        } else {
            map.domain_mapper.get(loopback)
        };
        target
    }

    pub async fn get_real_ip(&self, loopback: IpAddr) -> Option<IpAddr> {
        self.real_ip_mapper.get(loopback).await
    }

    pub async fn listen_and_serve(self: Arc<Self>, port: u16) -> oneshot::Receiver<()> {
        let (send, recv) = oneshot::channel();
        let addr = &format!("0.0.0.0:{}", port);
        let tcp_listener = TcpListener::bind(addr).await.unwrap();
        let tcp_port = tcp_listener.local_addr().unwrap().port();
        self.tcp_port.store(tcp_port, Ordering::SeqCst);
        let addr = &format!("0.0.0.0:{:?}", tcp_port);
        let udp_listener = UdpSocket::bind(addr).await.unwrap();
        let udp_port = udp_listener.local_addr().unwrap().port();
        self.udp_port.store(udp_port, Ordering::SeqCst);
        self.tcp_listener.set(Arc::new(tcp_listener)).unwrap();
        self.udp_listener.set(Arc::new(udp_listener)).unwrap();

        let proxy = self.clone();
        tokio::spawn({
            async move {
                let udp_socket_guard = proxy.udp_listener.get().unwrap();
                let proxy_buf = vec![0u8; 65535];
                loop {
                    let mut buf = vec![0u8; 4096];
                    match udp_socket_guard.recv_from(&mut buf).await {
                        Ok((size, src)) => {
                            let proxy_clone = Arc::clone(&proxy);
                            tokio::spawn(proxy_clone.handle_udp_packet(
                                buf,
                                proxy_buf.clone(),
                                size,
                                src,
                                udp_socket_guard.clone(),
                            ));
                        }
                        Err(e) => {
                            info!("recv_from failed: {}", e);
                            continue;
                        }
                    };
                }
            }
        });
        let proxy = self.clone();
        tokio::spawn({
            async move {
                let tcp_listener = self.tcp_listener.get().unwrap();
                let svr_cfg = ServerConfig::new(
                    Address::from(("127.0.0.1".to_string(), self.socks5_server_port as u16)),
                    "".to_string(),
                    CipherKind::NONE,
                );
                loop {
                    match tcp_listener.accept().await {
                        Ok((stream, src)) => {
                            let context = Context::new_shared(ServerType::Local);
                            let proxy_clone: Arc<Proxy> = Arc::clone(&proxy);
                            let svr_cfg = svr_cfg.clone();
                            stream.set_nodelay(true).unwrap();
                            tokio::spawn(async move {
                                proxy_clone.handle_tcp_stream(src, stream, svr_cfg, context).await;
                            });
                        }
                        Err(e) => {
                            error!("accept failed: {}", e);
                            continue;
                        }
                    };
                }
            }
        });
        match send.send(()) {
            Ok(_) => {}
            Err(_) => {
                error!("send failed");
            }
        }
        recv
    }

    pub fn tcp_port(&self) -> u16 {
        self.tcp_port.load(Ordering::SeqCst)
    }

    pub fn udp_port(&self) -> u16 {
        self.udp_port.load(Ordering::SeqCst)
    }
}
