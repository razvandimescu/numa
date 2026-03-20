use std::collections::HashMap;

use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct ServiceEntry {
    pub name: String,
    pub target_port: u16,
}

pub struct ServiceStore {
    entries: HashMap<String, ServiceEntry>,
}

impl Default for ServiceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceStore {
    pub fn new() -> Self {
        ServiceStore {
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: &str, target_port: u16) {
        let key = name.to_lowercase();
        self.entries.insert(
            key.clone(),
            ServiceEntry {
                name: key,
                target_port,
            },
        );
    }

    pub fn lookup(&self, name: &str) -> Option<&ServiceEntry> {
        self.entries.get(&name.to_lowercase())
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.entries.remove(&name.to_lowercase()).is_some()
    }

    pub fn list(&self) -> Vec<&ServiceEntry> {
        let mut entries: Vec<_> = self.entries.values().collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }
}
