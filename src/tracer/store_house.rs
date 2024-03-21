use dashmap::DashMap;

pub struct Storehouse {
    pub store: DashMap<i32, DashMap<i32, [u64; 6]>>,
}

impl Storehouse {
    pub fn new() -> Storehouse {
        Storehouse {
            store: DashMap::new(),
        }
    }

    pub fn save(&self, pid: i32, syscall_number: i32, args: [u64; 6]) {
        let pid_entry = self.store.entry(pid).or_insert_with(DashMap::new);
        pid_entry.insert(syscall_number, args);
    }

    pub fn get(&self, pid: i32, syscall_number: i32) -> Option<[u64; 6]> {
        self.store.get(&pid).and_then(|pid_entry| pid_entry.get(&syscall_number).map(|args| *args))
    }
}
