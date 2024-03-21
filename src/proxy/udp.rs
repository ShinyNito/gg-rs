use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use hickory_proto::{
    op::{Message, MessageType},
    rr::{rdata, DNSClass, RData, Record, RecordType},
};
use shadowsocks::{
    config::ServerType, context::Context, crypto::CipherKind, relay::Address, ProxySocket,
    ServerConfig,
};
use tokio::net::UdpSocket;
use tracing::{error, info, trace};

use super::Proxy;

pub async fn hijack_dns(data: &[u8]) -> (Result<Message, String>, bool) {
    let msg = match Message::from_vec(data) {
        Ok(msg) => msg,
        Err(e) => {
            trace!("Failed to parse DNS message: {}", e.to_string());
            return (Err(e.to_string()), false);
        }
    };
    if msg.query_count() == 0 {
        return (Err(("No question in DNS message").to_string()), true);
    }
    return (Ok(msg), true);
}

impl Proxy {
    pub async fn handle_udp_packet(
        self: Arc<Self>,
        buf: Vec<u8>,
        mut proxy_buf: Vec<u8>,
        size: usize,
        src: SocketAddr,
        udp_socket_guard: Arc<UdpSocket>,
    ) {
        let data = buf[..size].to_vec();
        let loopback = src.ip();
        let target = self.get_projection(loopback).await;
        if target.is_empty() {
            trace!(
                "[received udp] Processing received Error : Target is empty loopback: [{}]. src: [{:?}] -> dst: [{:?}]",
                loopback,
                src,
                target.clone()
            );
            return;
        }
        trace!(
            "[received udp] Processing received UDP packet: src: [{:?}] -> dst: [{:?}]",
            src,
            target
        );
        let (msg, is_dns) = hijack_dns(&data).await;
        if is_dns {
            let msg = match msg {
                Ok(msg) => msg,
                Err(e) => {
                    trace!(
                        "[received udp] src: [{:?}] -> dst: [{:?}], hijack dns failed: {}",
                        src,
                        target.clone(),
                        e
                    );
                    return;
                }
            };
            let query: &hickory_proto::op::Query = match msg.query() {
                Some(query) => query,
                None => {
                    trace!(
                        "[received udp] src: [{:?}] -> dst: [{:?}], No query found",
                        src,
                        target.clone(),
                    );
                    return;
                }
            };
            let fake_ip: Ipv4Addr;
            match query.query_type() {
                RecordType::A => {
                    let qname = query.name().to_string();
                    let dns_addr: SocketAddr = target.parse().expect("Invalid address");
                    let msg_buf = match msg.to_vec() {
                        Ok(msg_buf) => msg_buf,
                        Err(e) => {
                            trace!(
                                "[received udp] Failed to send DNS query : src: [{}] -> dst: [{}]. Error: {}",
                                src,
                                target.clone(),
                                e
                            );
                            return;
                        }
                    };
                    let dns_socks = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                    let mut buf = vec![0u8; 2 + 512];
                    match dns_socks.send_to(&msg_buf, dns_addr).await {
                        Ok(_) => {}
                        Err(e) => {
                            trace!(
                                "[received udp] Failed to send DNS query : src: [{}] -> dst: [{}]. Error: {}",
                                src,
                                target,
                                e
                            );
                            return;
                        }
                    }
                    match dns_socks.recv_from(&mut buf).await {
                        Ok((size, _)) => {
                            buf.truncate(size);
                        }
                        Err(e) => {
                            trace!(
                                "[received udp] Failed to receive DNS response : src: [{}] -> dst: [{}]. Error: {}",
                                src,
                                target,
                                e
                            );
                            return;
                        }
                    }
                    let dns_response = match Message::from_vec(&buf) {
                        Ok(msg) => msg,
                        Err(e) => {
                            trace!(
                                "[received udp] Failed to parse DNS response : src: [{}] -> dst: [{}]. Error: {}",
                                src,
                                target,
                                e
                            );
                            return;
                        }
                    };
                    drop(dns_socks);
                    if dns_response.answer_count() == 0 {
                        trace!(
                            "[received udp] No answer found : src: [{:?}] -> dst: [{:?}], domain: {}",
                            src,
                            target.clone(),
                            qname
                        );
                        let data = match dns_response.to_vec() {
                            Ok(data) => data,
                            Err(e) => {
                                trace!(
                                    "[received udp] Failed to parse DNS response : src: [{}] -> dst: [{}]. Error: {}",
                                    src,
                                    target,
                                    e
                                );
                                return;
                            }
                        };
                        let _ =udp_socket_guard.send_to(&data, src).await;
                        return;
                    }
                    for r in dns_response.answers() {
                        let rdata = match r.data() {
                            Some(rdata) => rdata,
                            None => {
                                info!("No question in DNS message");
                                return;
                            }
                        };
                        let domain = qname.trim_end_matches('.').to_string();
                        let fake_ip = match self.alloc_projection(domain.clone()).await {
                            IpAddr::V4(ip) => ip,
                            _ => {
                                return;
                            }
                        };
                        trace!("[hijackDNS] lookup: {} ->  {:?}", domain.clone(), fake_ip);
                        trace!("fakeIP: {}, realIP: {:?}", fake_ip, rdata);
                        match rdata {
                            RData::A(ip) => {
                                self.real_ip_mapper
                                    .set(IpAddr::V4(fake_ip), IpAddr::V4(**ip))
                                    .await;
                                let mut response = msg.clone();
                                response.set_message_type(MessageType::Response);
                                response
                                    .set_response_code(hickory_proto::op::ResponseCode::NoError);
                                response.add_answer(
                                    Record::new()
                                        .set_name(query.name().clone())
                                        .set_ttl(10)
                                        .set_rr_type(RecordType::A)
                                        .set_dns_class(DNSClass::IN)
                                        .set_data(Some(RData::A(rdata::A(fake_ip))))
                                        .clone(),
                                );
                                let data = match response.to_vec() {
                                    Ok(data) => data,
                                    Err(e) => {
                                        info!("to_vec failed: {}", e);
                                        return;
                                    }
                                };
                                match udp_socket_guard.send_to(&data, src).await {
                                    Ok(_) => {
                                        return;
                                    }
                                    Err(e) => info!("send_to failed: {}", e),
                                }
                            }
                            _ => {}
                        }
                    }
                }
                RecordType::AAAA => {
                    let qname = query.name().to_utf8();
                    let domain = qname.trim_end_matches('.').to_string();
                    fake_ip = match self.alloc_projection(domain).await {
                        IpAddr::V4(ip) => ip,
                        _ => {
                            return;
                        }
                    };
                    let fake_ip = fake_ip.to_ipv6_mapped();
                    let mut response = msg.clone();
                    response.set_message_type(MessageType::Response);
                    response.set_response_code(hickory_proto::op::ResponseCode::NoError);
                    response.set_recursion_available(true);
                    response.add_answer(
                        Record::new()
                            .set_name(query.name().clone())
                            .set_ttl(10)
                            .set_rr_type(RecordType::AAAA)
                            .set_dns_class(DNSClass::IN)
                            .set_data(Some(RData::AAAA(rdata::AAAA(fake_ip))))
                            .clone(),
                    );
                    let data = response.to_vec().unwrap();
                    match udp_socket_guard.send_to(&data, src).await {
                        Ok(_) => {
                            return;
                        }
                        Err(e) => info!("send_to failed: {}", e),
                    }
                    return;
                }
                _ => {
                }
            }
        }
        let mut parts = target.rsplitn(2, ':');
        let port_str = parts.next().ok_or("Missing port number").unwrap();
        let port: u16 = port_str.parse().expect("Invalid port number");
        let host = parts.next().ok_or("Missing host").unwrap().to_string();
        let target_addr = (host, port);
        let context = Context::new_shared(ServerType::Local);
        let mut svr_cfg = ServerConfig::new(
            Address::from(("127.0.0.1".to_string(), self.socks5_server_port as u16)),
            "".to_string(),
            CipherKind::NONE,
        );
        svr_cfg.set_timeout(std::time::Duration::from_secs(15));
        let proxy_socket = match ProxySocket::connect(context, &svr_cfg).await {
            Ok(proxy_socket) => proxy_socket,
            Err(e) => {
                error!(
                    "[udp relay] UDP Relay Error: Failed to connect Proxy. src: [{:?}] -> dst: [{:?}]. Err: {}.",
                    src,
                    target,
                    e
                );
                return;
            }
        };
        match proxy_socket.send(&Address::from(target_addr), &data).await {
            Ok(size) => {
                trace!(
                    "[udp relay] Success: Send UDP packet via proxy. src: [{:?}] -> dst: [{:?}], Bytes Received: {}",
                    src,
                    target,
                    size
                )
            }
            Err(e) => {
                error!(
                    "[udp relay] UDP Relay Error: Failed to send UDP packet. src: [{:?}] -> dst: [{:?}]. Err: {}.",
                    src, 
                    target,
                    e
                );
                return;
            }
        }

        let size = match proxy_socket.recv(&mut proxy_buf).await {
            Ok((size, _, _)) => {
                trace!(
                    "[udp relay] Success: Received UDP packet via proxy. src: [{:?}] -> dst: [{:?}], Bytes Received: {}",
                    src,
                    target,
                    size
                );
                size
            }
            Err(e) => {
                error!(
                    "[udp relay] UDP Relay Error: Failed to receive UDP packet. src: [{:?}] -> dst: [{:?}]. Err: {}.",
                    src, 
                    target,
                    e
                );
                return;
            }
        };
        
        match udp_socket_guard.send_to(&proxy_buf[..size], src).await {
            Ok(size) => {
                trace!(
                    "[udp relay] Success: Send UDP packet. src: [{:?}] -> dst: [{:?}], Bytes Received: {}",
                    src,
                    target,
                    size
                )
            }
            Err(e) => {
                error!(
                    "[udp relay] UDP Relay Error: Failed to send UDP packet. src: [{:?}] -> dst: [{:?}]. Err: {}.",
                    src, 
                    target,
                    e
                );
                return;
            }
        }
    }
}
