use dashmap::DashMap;
use ipnetwork::{IpNetwork, Ipv4Network};
use lazy_static::lazy_static;
use nix::{
    errno::Errno,
    libc::{self, pid_t, sockaddr, user_regs_struct, PTRACE_PEEKDATA},
    sys::{
        ptrace::{self, Options},
        signal::Signal,
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::Pid,
};
use std::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    {io, mem, ptr},
};
use tokio::{
    process::Command,
    sync::{mpsc, Mutex},
};
use tracing::{error, trace};
use zerocopy::{AsBytes, FromBytes, Ref};
use zerocopy_derive::{AsBytes, FromBytes, FromZeroes, Unaligned};

use crate::proxy::Proxy;

use self::store_house::Storehouse;

mod store_house;

lazy_static! {
    pub static ref RESERVED_PREFIX: IpNetwork =
        ipnetwork::IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(198, 18, 0, 0), 15).unwrap());
}

const DNS_PORT: u16 = 53;

#[derive(Clone, Debug)]
#[repr(C, packed)]
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
pub struct SocketMetadata {
    pub family: i32,
    pub type_: i32,
    pub protocol: i32,
}

#[repr(C, packed)]
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned, Debug)]
struct RawSockaddrInet4 {
    family: u16,
    port: [u8; 2],
    addr: [u8; 4],
    zero: [u8; 8],
}

#[repr(C, packed)]
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned, Debug)]
struct RawSockaddrInet6 {
    pub family: u16,
    pub port: [u8; 2],
    pub flowinfo: [u8; 4],
    pub addr: [u8; 16],
    pub scope_id: [u8; 4],
}

#[repr(C, packed)]
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
pub struct RawMsgHdr {
    msg_name: u64,
    len_msg_name: u32,
    msg_iov: u64,
    len_msg_iov: u64,
    msg_control: u64,
    len_msg_control: u64,
    flags: i32,
}

impl SocketMetadata {
    fn network(&self) -> &str {
        use libc::{IPPROTO_TCP, IPPROTO_UDP, IPPROTO_UDPLITE, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM};
        match self.type_ & (SOCK_STREAM | SOCK_DGRAM | SOCK_RAW) {
            SOCK_STREAM => match self.protocol {
                0 | IPPROTO_TCP => "tcp",
                _ => "",
            },
            SOCK_DGRAM => match self.protocol {
                0 | IPPROTO_UDP | IPPROTO_UDPLITE => "udp",
                _ => "",
            },
            SOCK_RAW => match self.protocol {
                IPPROTO_TCP => "tcp",
                IPPROTO_UDP | IPPROTO_UDPLITE => "udp",
                _ => "",
            },
            _ => "",
        }
    }
}

#[inline]
fn is_entry_stop(regs: user_regs_struct) -> bool {
    regs.rax as i64 == -libc::ENOSYS as i64
}

#[inline]
fn return_value_int(regs: user_regs_struct) -> Result<(i32, i32), nix::Error> {
    let rax_i32 = regs.rax as i32;
    if rax_i32 < 0 {
        let errno = -rax_i32;
        Err(nix::Error::from_raw(errno))
    } else {
        Ok((rax_i32, 0))
    }
}

#[inline]
fn poke_addr_to_argument(
    pid: i32,
    regs: &mut user_regs_struct,
    b_addr_to_poke: &[u8],
    p_sock_addr: u64,
    order_sock_addr_len: i32,
) -> Result<(), Box<dyn std::error::Error>> {
    let pid = Pid::from_raw(pid);
    let p_sock_addr = p_sock_addr as *mut c_void;
    for (i, &byte) in b_addr_to_poke.iter().enumerate() {
        let addr = unsafe { p_sock_addr.offset((i) as isize) };
        match unsafe { ptrace::write(pid, addr, byte as *mut _) } {
            Ok(_) => {}
            Err(err) => error!("pokeAddrToArgument: {:?}", err),
        }
    }
    if (order_sock_addr_len as i64) == b_addr_to_poke.len() as i64 {
        return Ok(());
    }
    set_argument(
        regs,
        order_sock_addr_len.try_into().unwrap(),
        b_addr_to_poke.len() as u64,
    );

    ptrace::setregs(pid, *regs)?;
    Ok(())
}

#[inline]
fn set_argument(regs: &mut user_regs_struct, order: i32, value: u64) {
    match order {
        0 => {
            regs.rdi = value;
        }
        1 => {
            regs.rsi = value;
        }
        2 => {
            regs.rdx = value;
        }
        3 => {
            regs.r10 = value;
        }
        4 => {
            regs.r8 = value;
        }
        5 => {
            regs.r9 = value;
        }
        _ => {}
    }
}

#[inline]
fn read_sockaddr(pid: i32, p_sock_addr: u64, sock_addr: &mut [u8]) -> Result<(), io::Error> {
    let word_size = mem::size_of::<u64>() as u64;
    let sock_addr_len = sock_addr.len() as u64;
    let word_count = (sock_addr_len + word_size - 1) / word_size;

    let pid_fd = Pid::from_raw(pid);

    for i in 0..word_count {
        let current_addr = p_sock_addr + i * word_size;
        let addr = current_addr as *mut libc::c_void;

        let data = match ptrace::read(pid_fd, addr) {
            Ok(data) => data as u64,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "PtracePeekData failed",
                ))
            }
        };

        let data_bytes = data.to_ne_bytes();
        let start = (i * word_size) as usize;
        let end = std::cmp::min(start + word_size as usize, sock_addr_len as usize);

        sock_addr[start..end].copy_from_slice(&data_bytes[..end - start]);
    }

    Ok(())
}

#[inline]
fn peek_data(pid: pid_t, addr: u64, data: &mut [u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }

    let word_size = mem::size_of::<libc::c_long>();
    let mut error_occurred = false;

    for (i, chunk) in data.chunks_mut(word_size).enumerate() {
        let word_addr = addr + (i * word_size) as u64;

        unsafe {
            let word = libc::ptrace(
                PTRACE_PEEKDATA,
                pid,
                word_addr as *mut c_void,
                ptr::null_mut::<c_void>(),
            );

            if word == -1i64 as libc::c_long && Errno::last_raw() != 0 {
                error_occurred = true;
                break;
            }
            let bytes: [u8; mem::size_of::<libc::c_long>()] = mem::transmute(word.to_ne_bytes());
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
    }

    if error_occurred {
        Err("PtracePeekData failed".into())
    } else {
        Ok(())
    }
}

#[inline]
fn argument(regs: &libc::user_regs_struct, order: usize) -> u64 {
    let args_mapper = arguments(regs);
    *args_mapper.get(order).unwrap_or(&args_mapper[0])
}

#[inline]
fn arguments(regs: &libc::user_regs_struct) -> [u64; 6] {
    [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]
}

#[inline]
fn inst(regs: user_regs_struct) -> i32 {
    regs.orig_rax as i32
}

pub struct Tracer {
    pub process_info: Arc<Mutex<Command>>,
    pub socket_info: Arc<DashMap<i32, DashMap<i32, SocketMetadata>>>,
    pub store_house: Arc<Storehouse>,
    pub proxy: Arc<Proxy>,
}

impl Tracer {
    pub fn new(program_name: &str, program_args: Vec<&str>, socks5_port: usize) -> Tracer {
        let mut command = Command::new(program_name);
        command.kill_on_drop(true);
        command.args(program_args);
        let proxy = Proxy::new(socks5_port);
        let t = Tracer {
            process_info: Arc::new(Mutex::new(command)),
            socket_info: Arc::new(DashMap::new()),
            proxy: Arc::new(proxy),
            store_house: Arc::new(Storehouse::new()),
        };
        t
    }

    async fn spawn_blocking_with_wait(
    ) -> Result<WaitStatus, Box<dyn std::error::Error + Send + Sync>> {
        tokio::task::spawn_blocking(|| {
            match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
                Ok(status) => Ok(status),
                Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
            }
        })
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        .and_then(|result| result)
    }

    pub async fn trace(&self) {
        let command = match self.process_info.lock().await.spawn() {
            Ok(command) => command,
            Err(e) => {
                error!("Failed to spawn process: {:?}", e);
                return;
            }
        };
        let pid = Pid::from_raw(command.id().expect("Failed to get process id") as i32);
        let _ = ptrace::attach(pid);
        waitpid(pid, None).expect("Failed to waitpid");
        let options = Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACEEXEC;
        match ptrace::setoptions(pid, options) {
            Ok(_) => (),
            Err(e) => {
                tracing::error!("Failed to set options for pid: {:?}, error: {:?}", pid, e);
                return;
            }
        }
        ptrace::syscall(pid, None).expect("Failed to deliver signal");
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let status = Tracer::spawn_blocking_with_wait().await;
                match status {
                    Ok(status) => {
                        tx.send(status).unwrap();
                    }
                    Err(_) => {
                        return;
                    }
                }
            }
        });

        while let Some(status) = rx.recv().await {
            let child_pid = status.pid().unwrap();
            let child_pid_i32 = child_pid.as_raw();
            if self.get_socket_info(child_pid.as_raw(), 0).await.is_none() {
                self.save_socket_info(
                    child_pid_i32,
                    0,
                    SocketMetadata {
                        family: libc::AF_LOCAL,
                        type_: libc::SOCK_RAW,
                        protocol: 0,
                    },
                )
                .await;
                self.save_socket_info(
                    child_pid_i32,
                    1,
                    SocketMetadata {
                        family: libc::AF_LOCAL,
                        type_: libc::SOCK_RAW,
                        protocol: 0,
                    },
                )
                .await;
                self.save_socket_info(
                    child_pid_i32,
                    2,
                    SocketMetadata {
                        family: libc::AF_LOCAL,
                        type_: libc::SOCK_RAW,
                        protocol: 0,
                    },
                )
                .await;
            }
            match status {
                WaitStatus::Exited(child_pid, _) => {
                    self.remove_process_socket_info(child_pid.into()).await;
                    if pid == child_pid {
                        return;
                    }
                }
                WaitStatus::Signaled(child_pid, _, _) => {
                    self.remove_process_socket_info(child_pid.into()).await;
                    if pid == child_pid {
                        return;
                    }
                }
                WaitStatus::Stopped(child_pid, signal) => {
                    let mut sig = None;
                    if signal == Signal::SIGTRAP {
                        let regs = match ptrace::getregs(child_pid) {
                            Ok(regs) => regs,
                            Err(e) => {
                                error!("[PtraceGetRegs] fail: {:?}", e);
                                return;
                            }
                        };
                        if is_entry_stop(regs) {
                            self.entry_handler(child_pid.into(), regs).await;
                        } else {
                            self.exit_handler(child_pid.into(), regs).await;
                        }
                    } else {
                        sig = Some(signal);
                        match signal {
                            Signal::SIGSTOP => sig = None,
                            _ => {}
                        }
                    }
                    ptrace::syscall(child_pid, sig).expect("Failed to deliver signal");
                }
                WaitStatus::PtraceEvent(child_pid, signal, libc::PTRACE_EVENT_CLONE) => {
                    ptrace::syscall(child_pid, signal).expect("Failed to deliver signal");
                }
                WaitStatus::PtraceSyscall(child_pid) => {
                    ptrace::syscall(child_pid, None).expect("Failed to deliver signal");
                }
                _ => {}
            }
        }
    }

    pub async fn get_socket_info(&self, pid: i32, socket_fd: i32) -> Option<SocketMetadata> {
        match self.socket_info.get(&pid) {
            Some(socket_info_entry) => match socket_info_entry.get(&socket_fd) {
                Some(socket_info) => Some(socket_info.clone()),
                None => None,
            },
            None => None,
        }
    }

    async fn save_socket_info(&self, pid: i32, socket_fd: i32, metadata: SocketMetadata) {
        let socket_info_entry = self.socket_info.entry(pid).or_insert_with(DashMap::new);
        socket_info_entry.insert(socket_fd, metadata.clone());
    }

    async fn check_socket(&self, pid: i32, fd: i32) -> (Option<SocketMetadata>, bool) {
        let socket_info = self.get_socket_info(pid, fd).await;
        match socket_info {
            Some(info) => match info.family {
                libc::AF_INET | libc::AF_INET6 => match info.network() {
                    "tcp" | "udp" => (Some(info), true),
                    _ => (None, false),
                },
                _ => (None, false),
            },
            None => (None, false),
        }
    }

    async fn remove_socket_info(&self, pid: i32, socket_fd: i32) {
        if let Some(sockets) = self.socket_info.get_mut(&pid) {
            sockets.remove(&socket_fd);
            if sockets.is_empty() {
                self.socket_info.remove(&pid);
            }
        }
    }

    async fn remove_process_socket_info(&self, pid: i32) {
        if let Some(sockets) = self.socket_info.get(&pid) {
            if sockets.is_empty() {
                self.socket_info.remove(&pid);
            }
        }
    }

    fn port_hack_to(&self, socket_info: &SocketMetadata) -> u16 {
        match socket_info.network() {
            "tcp" => {
                return self.proxy.tcp_port();
            }
            "udp" => {
                return self.proxy.udp_port();
            }
            _ => 0,
        }
    }

    async fn handle_inet4(
        &self,
        socket_info: &SocketMetadata,
        b_sock_addr: &mut [u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if b_sock_addr.len() < std::mem::size_of::<RawSockaddrInet4>() {
            return Err("Invalid RawSockaddrInet4: Buffer too short".into());
        }

        let network: &str = socket_info.network();
        let port_hack_to: u16 = self.port_hack_to(socket_info);

        let addr = RawSockaddrInet4::mut_from(b_sock_addr)
            .ok_or_else(|| "Invalid RawSockaddrInet4".to_string())?;
        let target_port = u16::from_be_bytes(addr.port);

        if network == "udp" && target_port == 0 {
            return Ok(vec![]);
        }
        let ip = Ipv4Addr::from(addr.addr);

        if ip.is_loopback() && !(network == "udp" && target_port == DNS_PORT) {
            return Ok(vec![]);
        }
        let mut origin_addr = ip.to_string();
        if network == "tcp" || network == "udp" {
            if crate::tracer::RESERVED_PREFIX.contains(std::net::IpAddr::V4(ip)) {
                origin_addr = self.proxy.get_projection(IpAddr::V4(ip)).await;
            }
            let loopback = self
                .proxy
                .alloc_projection(format!("{}:{}", origin_addr, target_port))
                .await;
            origin_addr = loopback.to_string();
        } else if crate::tracer::RESERVED_PREFIX.contains(std::net::IpAddr::V4(ip)) {
            let loopback = self.proxy.get_real_ip(IpAddr::V4(ip)).await.unwrap();
            origin_addr = loopback.to_string();
        }
        let ip_bytes: [u8; 4] = match origin_addr.parse() {
            Ok(IpAddr::V4(ipv4)) => ipv4.octets(),
            _ => {
                return Err("Invalid IP address".into());
            }
        };
        addr.port.copy_from_slice(&port_hack_to.to_be_bytes());
        addr.addr.copy_from_slice(&ip_bytes);
        Ok(addr.as_bytes().to_vec())
    }

    async fn handle_inet6(
        &self,
        socket_info: &SocketMetadata,
        b_sock_addr: &mut [u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let network: &str = socket_info.network();
        let port_hack_to: u16 = self.port_hack_to(socket_info);
        let addr = RawSockaddrInet6::mut_from(b_sock_addr)
            .ok_or_else(|| "Invalid RawSockaddrInet6".to_string())?;
        let target_port = u16::from_be_bytes(addr.port);
        if network == "udp" && target_port == 0 {
            trace!("SKIP:  UDP port is 0");
            return Ok(vec![]);
        }
        let ipv6: Ipv6Addr = Ipv6Addr::from(addr.addr);
        let ip: IpAddr = match ipv6.to_ipv4() {
            Some(ipv4)
                if ipv6.segments()[0..5] == [0, 0, 0, 0, 0] && ipv6.segments()[5] == 0xffff =>
            {
                IpAddr::V4(ipv4)
            }
            _ => IpAddr::V6(ipv6),
        };
        if !(network == "udp" && target_port == DNS_PORT) && ip.is_loopback() {
            trace!("SKIP: Loopback {:?}", ip);
            return Ok(vec![]);
        }
        let origin_addr = if crate::tracer::RESERVED_PREFIX.contains(ip) {
            self.proxy.get_projection(ip).await
        } else {
            ipv6.to_string()
        };
        let loopback: IpAddr = self
            .proxy
            .alloc_projection(format!("{}:{}", origin_addr, target_port))
            .await;
        let ip_bytes = match loopback {
            IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped().octets(),
            IpAddr::V6(ipv6) => ipv6.octets(),
        };
        addr.port.copy_from_slice(&port_hack_to.to_be_bytes());
        addr.addr.copy_from_slice(&ip_bytes);
        Ok(addr.as_bytes().to_vec())
    }

    async fn entry_handler(&self, pid: i32, mut regs: user_regs_struct) {
        let args = arguments(&regs);
        let inst = inst(regs);
        match inst as i64 {
            libc::SYS_socket | libc::SYS_fcntl => {
                self.store_house.save(pid, inst, args);
            }
            libc::SYS_connect | libc::SYS_sendto => {
                let fd = args[0] as i32;
                let (socket_info, ok) = self.check_socket(pid, fd).await;
                if !ok {
                    return;
                }
                let socket_info = match socket_info {
                    Some(socket_info) => socket_info,
                    None => {
                        return;
                    }
                };

                let (p_sock_addr, sock_addr_len, order_sock_addr_len): (u64, u64, i32);

                if inst as i64 == libc::SYS_connect {
                    p_sock_addr = args[1];
                    sock_addr_len = args[2];
                    order_sock_addr_len = 2;
                } else {
                    p_sock_addr = args[4];
                    sock_addr_len = args[5];
                    order_sock_addr_len = 5;
                    if sock_addr_len == 0 {
                        return;
                    }
                }
                let mut b_sockaddr = vec![0u8; sock_addr_len as usize];
                match read_sockaddr(pid, p_sock_addr, &mut b_sockaddr) {
                    Err(_e) => {
                        return;
                    }
                    Ok(_) => {}
                };
                let sock_addr: &sockaddr = unsafe { &*(b_sockaddr.as_ptr() as *const sockaddr) };
                match sock_addr.sa_family as i32 {
                    libc::AF_INET => {
                        let b_sock_addr_to_pock =
                            match self.handle_inet4(&socket_info, &mut b_sockaddr).await {
                                Ok(b_sock_addr_to_pock) => b_sock_addr_to_pock,
                                Err(e) => {
                                    trace!("[handleINet4]: {:?}", e);
                                    return;
                                }
                            };
                        match poke_addr_to_argument(
                            pid,
                            &mut regs,
                            &b_sock_addr_to_pock,
                            p_sock_addr,
                            order_sock_addr_len,
                        ) {
                            Ok(_) => {}
                            Err(e) => {
                                error!("Failed to poke addr to argument: {:?}", e);
                                return;
                            }
                        }
                    }
                    libc::AF_INET6 => {
                        let b_sock_addr_to_pock =
                            match self.handle_inet6(&socket_info, &mut b_sockaddr).await {
                                Ok(b_sock_addr_to_pock) => b_sock_addr_to_pock,
                                Err(e) => {
                                    error!("Failed to handle inet6: {:?}", e);
                                    return;
                                }
                            };

                        if b_sock_addr_to_pock.is_empty() {
                            return;
                        }
                        match poke_addr_to_argument(
                            pid,
                            &mut regs,
                            &b_sock_addr_to_pock,
                            p_sock_addr,
                            order_sock_addr_len,
                        ) {
                            Ok(_) => {}
                            Err(e) => {
                                error!("Failed to poke addr to argument: {:?}", e);
                                return;
                            }
                        }
                    }
                    _ => {}
                }
            }

            libc::SYS_sendmsg => {
                let fd = args[0] as i32;
                let (socket_info, ok) = self.check_socket(pid, fd).await;
                if !ok {
                    ()
                }
                let socket_info = match socket_info {
                    Some(socket_info) => socket_info,
                    None => {
                        return;
                    }
                };
                let p_msg = args[1];
                let mut b_msg = vec![0; mem::size_of::<RawMsgHdr>()];
                match peek_data(pid, p_msg, &mut b_msg) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Failed to peek data: {:?}", e);
                        ()
                    }
                };
                let msg: Ref<&[u8], RawMsgHdr> = Ref::new(&*b_msg).expect("Invalid RawMsgHdr");
                if msg.len_msg_name == 0 {
                    return;
                }
                let mut b_sock_addr = vec![0u8; msg.len_msg_name as usize];
                match peek_data(pid, msg.msg_name, &mut b_sock_addr) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Failed to peek data: {:?}", e);
                        return;
                    }
                };
                let sock_addr: &sockaddr = unsafe { &*(b_sock_addr.as_ptr() as *const sockaddr) };
                match sock_addr.sa_family as i32 {
                    libc::AF_INET => {
                        let mut b_sock_addr_to_pock =
                            match self.handle_inet4(&socket_info, &mut b_sock_addr).await {
                                Ok(b_sock_addr_to_pock) => b_sock_addr_to_pock,
                                Err(e) => {
                                    error!("Failed to handle inet4: {:?}", e);
                                    return;
                                }
                            };
                        if b_sock_addr_to_pock.is_empty() {
                            return;
                        }
                        match peek_data(pid, msg.msg_name, &mut b_sock_addr_to_pock) {
                            Ok(_) => {}
                            Err(e) => {
                                error!("Failed to peek data: {:?}", e);
                                return;
                            }
                        }
                    }
                    libc::AF_INET6 => {
                        let mut b_sock_addr_to_pock =
                            match self.handle_inet6(&socket_info, &mut b_sock_addr).await {
                                Ok(b_sock_addr_to_pock) => b_sock_addr_to_pock,
                                Err(e) => {
                                    error!("Failed to handle inet6: {:?}", e);
                                    return;
                                }
                            };

                        if b_sock_addr_to_pock.is_empty() {
                            return;
                        }
                        match peek_data(pid, msg.msg_name, &mut b_sock_addr_to_pock) {
                            Ok(_) => {}
                            Err(e) => {
                                error!("Failed to peek data: {:?}", e);
                                return;
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    async fn exit_handler(&self, pid: i32, regs: user_regs_struct) {
        let inst = inst(regs);
        match inst as i64 {
            libc::SYS_socket => {
                let socket_args = match self.store_house.get(pid, inst) {
                    Some(socket_args) => socket_args,
                    None => {
                        return;
                    }
                };
                let fd = match return_value_int(regs) {
                    Ok((fd, _)) => fd as i32,
                    Err(_) => {
                        return;
                    }
                };
                let socks_info = SocketMetadata {
                    family: socket_args[0] as i32,
                    type_: socket_args[1] as i32,
                    protocol: socket_args[2] as i32,
                };
                self.save_socket_info(pid, fd, socks_info).await;
            }
            libc::SYS_fcntl => {
                let args = match self.store_house.get(pid, inst) {
                    Some(args) => args,
                    None => {
                        error!("Failed to get fcntl args");
                        return;
                    }
                };
                match args[1] as i32 {
                    libc::F_DUPFD | libc::F_DUPFD_CLOEXEC => {}
                    _ => {
                        return;
                    }
                }
                let fd = args[0] as i32;
                let socket_info = match self.get_socket_info(pid, fd).await {
                    Some(socket_info) => socket_info,
                    None => {
                        error!("Failed to get socket info {:?}, fd {:?}", pid, fd);
                        return;
                    }
                };
                let new_fd = match return_value_int(regs) {
                    Ok((fd, _)) => fd,
                    Err(e) => {
                        error!("Failed to get return value: {:?}", e);
                        return;
                    }
                };
                self.save_socket_info(pid, new_fd as i32, socket_info).await;
            }
            libc::SYS_close => {
                let fd = argument(&regs, 0) as i32;
                self.remove_socket_info(pid, fd).await;
            }
            _ => {}
        }
    }
}
