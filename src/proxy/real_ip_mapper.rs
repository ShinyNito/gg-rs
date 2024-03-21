use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::Mutex;

pub struct RealIPMapper {
    mapper: Arc<Mutex<HashMap<IpAddr, IpAddr>>>,
}

impl RealIPMapper {
    pub fn new() -> Self {
        Self {
            mapper: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn set(&self, loopback: IpAddr, real: IpAddr) {
        let mut mapper = self.mapper.lock().await;
        mapper.insert(loopback, real);
    }

    pub async fn get(&self, loopback: IpAddr) -> Option<IpAddr> {
        let mapper = self.mapper.lock().await;
        mapper.get(&loopback).cloned()
    }
}
