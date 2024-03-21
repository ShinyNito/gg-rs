use tracing::trace;

use crate::proxy::IPMapper;
use crate::tracer::RESERVED_PREFIX;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;

pub struct LoopbackMapper {
    pub mapper: HashMap<IpAddr, String>,
    pub rev_mapper: HashMap<String, IpAddr>,
    pub last_alloc: IpAddr,
}

impl IPMapper for LoopbackMapper {
    fn alloc(&mut self, target: String) -> IpAddr {
        if let Some(loopback) = self.rev_mapper.get(&target) {
            return *loopback;
        }
        let last_alloc = self.last_alloc;
        let next_alloc = match last_alloc {
            IpAddr::V4(ip) => {
                let num = u32::from_be_bytes(ip.octets());
                let next_num = num.wrapping_add(1);
                IpAddr::V4(Ipv4Addr::from(next_num.to_be_bytes()))
            }
            IpAddr::V6(_) => panic!("IPv6 is not supported"),
        };
        if !next_alloc.is_loopback() {
            self.last_alloc = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        } else {
            self.last_alloc = next_alloc;
        }
        self.mapper.insert(self.last_alloc, target.clone());
        self.rev_mapper.insert(target, self.last_alloc);
        self.last_alloc
    }

    fn get(&self, loopback: IpAddr) -> String {
        match self.mapper.get(&loopback) {
            Some(target) => target.to_string(),
            None => "".to_string(),
        }
    }
}

pub fn new_loopback_mapper() -> Box<LoopbackMapper> {
    let last_alloc = IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1));
    Box::new(LoopbackMapper {
        mapper: HashMap::new(),
        rev_mapper: HashMap::new(),
        last_alloc,
    })
}

pub struct ReservedMapper {
    pub mapper: HashMap<IpAddr, String>,
    pub rev_mapper: HashMap<String, IpAddr>,
    pub last_alloc: IpAddr,
}

pub fn new_reserved_mapper() -> Box<ReservedMapper> {
    let last_alloc = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
    Box::new(ReservedMapper {
        mapper: HashMap::new(),
        rev_mapper: HashMap::new(),
        last_alloc,
    })
}

impl IPMapper for ReservedMapper {
    fn alloc(&mut self, target: String) -> IpAddr {
        if let Some(loopback) = self.rev_mapper.get(&target) {
            return *loopback;
        }
        let last_alloc = self.last_alloc;
        self.last_alloc = match last_alloc {
            IpAddr::V4(ip) => {
                let num = u32::from_be_bytes(ip.octets());
                let next_num = num.wrapping_add(1);
                IpAddr::V4(Ipv4Addr::from(next_num.to_be_bytes()))
            }
            IpAddr::V6(_) => {
                panic!("IPv6 is not supported");
            }
        };
        trace!("next_alloc: {:?}", self.last_alloc);
        match self.last_alloc {
            IpAddr::V4(ip) => {
                if !RESERVED_PREFIX.contains(std::net::IpAddr::V4(ip)) {
                    self.last_alloc = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
                }
                self.mapper.insert(self.last_alloc, target.clone());
                self.rev_mapper.insert(target, self.last_alloc);
                self.last_alloc
            }
            IpAddr::V6(_) => {
                panic!("IPv6 is not supported");
            }
        }
    }

    fn get(&self, loopback: IpAddr) -> String {
        match self.mapper.get(&loopback) {
            Some(target) => target.to_string(),
            None => "".to_string(),
        }
    }
}

pub struct Mapper {
    pub addr_mapper: Box<LoopbackMapper>,
    pub domain_mapper: Box<ReservedMapper>,
}

impl Mapper {
    pub fn new() -> Mapper {
        let addr_mapper = new_loopback_mapper();
        let domain_mapper = new_reserved_mapper();
        Mapper {
            addr_mapper,
            domain_mapper,
        }
    }
}