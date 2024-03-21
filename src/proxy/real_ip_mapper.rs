use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;

pub struct RealIPMapper {
    mapper: Arc<DashMap<IpAddr, IpAddr>>,
}

impl RealIPMapper {
    pub fn new() -> Self {
        Self {
            mapper: Arc::new(DashMap::new()),
        }
    }

    pub async fn set(&self, loopback: IpAddr, real: IpAddr) {
        self.mapper.insert(loopback, real);
    }

    pub async fn get(&self, loopback: IpAddr) -> Option<IpAddr> {
        self.mapper.get(&loopback).map(|entry| *entry.value())
    }
}
