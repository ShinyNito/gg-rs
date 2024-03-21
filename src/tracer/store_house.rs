use std::{collections::HashMap, sync::Mutex};

pub struct Storehouse {
    pub store: Mutex<HashMap<i32, HashMap<i32, [u64; 6]>>>,
}

impl Storehouse {
    pub fn new() -> Storehouse {
        Storehouse {
            store: Mutex::new(HashMap::new()),
        }
    }
    pub fn save(&self, pid: i32, syscall_number: i32, args: [u64; 6]) {
        let mut store = self.store.lock().unwrap();
        let pid_entry = store.entry(pid).or_insert_with(HashMap::new);
        pid_entry.insert(syscall_number, args);
    }
    pub fn get(&self, pid: i32, syscall_number: i32) -> Option<[u64; 6]> {
        let store = self.store.lock().unwrap();
        match store.get(&pid) {
            Some(pid_entry) => {
                let syscall_entry = pid_entry.get(&syscall_number);
                match syscall_entry {
                    Some(args) => Some(args.clone()),
                    None => None,
                }
            }
            None => None,
        }
    }
}
