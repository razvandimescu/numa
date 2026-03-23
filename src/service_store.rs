use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use log::{info, warn};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    pub target_port: u16,
    #[serde(default)]
    pub routes: Vec<RouteEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub path: String,
    pub port: u16,
    #[serde(default)]
    pub strip: bool,
}

impl ServiceEntry {
    /// Resolve backend port and (possibly rewritten) path for a request
    pub fn resolve_route(&self, request_path: &str) -> (u16, String) {
        // Longest prefix match
        let matched = self
            .routes
            .iter()
            .filter(|r| {
                request_path == r.path
                    || request_path.starts_with(&r.path)
                        && (r.path.ends_with('/')
                            || request_path.as_bytes().get(r.path.len()) == Some(&b'/'))
            })
            .max_by_key(|r| r.path.len());

        match matched {
            Some(route) => {
                let path = if route.strip {
                    let stripped = &request_path[route.path.len()..];
                    if stripped.is_empty() || !stripped.starts_with('/') {
                        format!("/{}", stripped.trim_start_matches('/'))
                    } else {
                        stripped.to_string()
                    }
                } else {
                    request_path.to_string()
                };
                (route.port, path)
            }
            None => (self.target_port, request_path.to_string()),
        }
    }
}

pub struct ServiceStore {
    entries: HashMap<String, ServiceEntry>,
    /// Services defined in numa.toml (not persisted to user file)
    config_services: HashSet<String>,
    persist_path: PathBuf,
}

impl Default for ServiceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceStore {
    pub fn new() -> Self {
        let persist_path = dirs_path();
        ServiceStore {
            entries: HashMap::new(),
            config_services: HashSet::new(),
            persist_path,
        }
    }

    /// Insert a service from numa.toml config (not persisted)
    pub fn insert_from_config(&mut self, name: &str, target_port: u16, routes: Vec<RouteEntry>) {
        let key = name.to_lowercase();
        self.config_services.insert(key.clone());
        self.entries.insert(
            key.clone(),
            ServiceEntry {
                name: key,
                target_port,
                routes,
            },
        );
    }

    /// Insert a user-defined service (persisted to ~/.config/numa/services.json)
    pub fn insert(&mut self, name: &str, target_port: u16) {
        let key = name.to_lowercase();
        self.entries.insert(
            key.clone(),
            ServiceEntry {
                name: key,
                target_port,
                routes: Vec::new(),
            },
        );
        self.save();
    }

    pub fn add_route(&mut self, service: &str, path: String, port: u16, strip: bool) -> bool {
        let key = service.to_lowercase();
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.routes.retain(|r| r.path != path);
            entry.routes.push(RouteEntry { path, port, strip });
            self.save();
            true
        } else {
            false
        }
    }

    pub fn remove_route(&mut self, service: &str, path: &str) -> bool {
        let key = service.to_lowercase();
        if let Some(entry) = self.entries.get_mut(&key) {
            let before = entry.routes.len();
            entry.routes.retain(|r| r.path != path);
            if entry.routes.len() < before {
                self.save();
                return true;
            }
        }
        false
    }

    pub fn lookup(&self, name: &str) -> Option<&ServiceEntry> {
        self.entries.get(&name.to_lowercase())
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let key = name.to_lowercase();
        let removed = self.entries.remove(&key).is_some();
        if removed {
            self.save();
        }
        removed
    }

    pub fn list(&self) -> Vec<&ServiceEntry> {
        let mut entries: Vec<_> = self.entries.values().collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    /// Load user-defined services from ~/.config/numa/services.json
    pub fn load_persisted(&mut self) {
        if !self.persist_path.exists() {
            return;
        }
        match std::fs::read_to_string(&self.persist_path) {
            Ok(contents) => match serde_json::from_str::<Vec<ServiceEntry>>(&contents) {
                Ok(entries) => {
                    let count = entries.len();
                    for entry in entries {
                        let key = entry.name.to_lowercase();
                        // Don't overwrite config-defined services
                        if !self.config_services.contains(&key) {
                            self.entries.insert(key, entry);
                        }
                    }
                    if count > 0 {
                        info!(
                            "loaded {} persisted services from {:?}",
                            count, self.persist_path
                        );
                    }
                }
                Err(e) => warn!("failed to parse {:?}: {}", self.persist_path, e),
            },
            Err(e) => warn!("failed to read {:?}: {}", self.persist_path, e),
        }
    }

    /// Save user-defined services (excluding config and "numa") to disk
    fn save(&self) {
        let user_services: Vec<&ServiceEntry> = self
            .entries
            .values()
            .filter(|e| !self.config_services.contains(&e.name))
            .collect();

        if let Some(parent) = self.persist_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match serde_json::to_string_pretty(&user_services) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.persist_path, json) {
                    warn!("failed to save services to {:?}: {}", self.persist_path, e);
                }
            }
            Err(e) => warn!("failed to serialize services: {}", e),
        }
    }
}

fn dirs_path() -> PathBuf {
    crate::config_dir().join("services.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn entry(port: u16, routes: Vec<RouteEntry>) -> ServiceEntry {
        ServiceEntry {
            name: "app".into(),
            target_port: port,
            routes,
        }
    }

    fn route(path: &str, port: u16, strip: bool) -> RouteEntry {
        RouteEntry {
            path: path.into(),
            port,
            strip,
        }
    }

    fn test_store() -> ServiceStore {
        ServiceStore {
            entries: HashMap::new(),
            config_services: HashSet::new(),
            persist_path: PathBuf::from("/dev/null"),
        }
    }

    // --- resolve_route ---

    #[test]
    fn no_routes_returns_default_port() {
        let e = entry(3000, vec![]);
        assert_eq!(e.resolve_route("/anything"), (3000, "/anything".into()));
    }

    #[test]
    fn exact_match() {
        let e = entry(3000, vec![route("/api", 4000, false)]);
        assert_eq!(e.resolve_route("/api"), (4000, "/api".into()));
    }

    #[test]
    fn prefix_match() {
        let e = entry(3000, vec![route("/api", 4000, false)]);
        assert_eq!(e.resolve_route("/api/users"), (4000, "/api/users".into()));
    }

    #[test]
    fn segment_boundary_rejects_partial() {
        let e = entry(3000, vec![route("/api", 4000, false)]);
        // /apiary must NOT match /api — different segment
        assert_eq!(e.resolve_route("/apiary"), (3000, "/apiary".into()));
    }

    #[test]
    fn segment_boundary_rejects_apikey() {
        let e = entry(3000, vec![route("/api", 4000, false)]);
        assert_eq!(e.resolve_route("/apikey"), (3000, "/apikey".into()));
    }

    #[test]
    fn longest_prefix_wins() {
        let e = entry(
            3000,
            vec![route("/api", 4000, false), route("/api/v2", 5000, false)],
        );
        assert_eq!(
            e.resolve_route("/api/v2/users"),
            (5000, "/api/v2/users".into())
        );
        // shorter prefix still works for non-v2 paths
        assert_eq!(
            e.resolve_route("/api/v1/users"),
            (4000, "/api/v1/users".into())
        );
    }

    #[test]
    fn strip_removes_prefix() {
        let e = entry(3000, vec![route("/api", 4000, true)]);
        assert_eq!(e.resolve_route("/api/users"), (4000, "/users".into()));
    }

    #[test]
    fn strip_exact_path_gives_root() {
        let e = entry(3000, vec![route("/api", 4000, true)]);
        assert_eq!(e.resolve_route("/api"), (4000, "/".into()));
    }

    #[test]
    fn trailing_slash_route_matches() {
        let e = entry(3000, vec![route("/app/", 4000, false)]);
        assert_eq!(
            e.resolve_route("/app/dashboard"),
            (4000, "/app/dashboard".into())
        );
    }

    // --- ServiceStore: add_route / remove_route ---

    #[test]
    fn add_route_to_existing_service() {
        let mut store = test_store();
        store.insert_from_config("app", 3000, vec![]);
        assert!(store.add_route("app", "/api".into(), 4000, false));
        let entry = store.lookup("app").unwrap();
        assert_eq!(entry.routes.len(), 1);
        assert_eq!(entry.routes[0].path, "/api");
    }

    #[test]
    fn add_route_to_missing_service_returns_false() {
        let mut store = test_store();
        assert!(!store.add_route("ghost", "/api".into(), 4000, false));
    }

    #[test]
    fn add_route_deduplicates_by_path() {
        let mut store = test_store();
        store.insert_from_config("app", 3000, vec![]);
        store.add_route("app", "/api".into(), 4000, false);
        store.add_route("app", "/api".into(), 5000, true);
        let entry = store.lookup("app").unwrap();
        assert_eq!(entry.routes.len(), 1);
        assert_eq!(entry.routes[0].port, 5000);
        assert!(entry.routes[0].strip);
    }

    #[test]
    fn remove_route_returns_true_when_found() {
        let mut store = test_store();
        store.insert_from_config("app", 3000, vec![route("/api", 4000, false)]);
        assert!(store.remove_route("app", "/api"));
        assert!(store.lookup("app").unwrap().routes.is_empty());
    }

    #[test]
    fn remove_route_returns_false_when_missing() {
        let mut store = test_store();
        store.insert_from_config("app", 3000, vec![]);
        assert!(!store.remove_route("app", "/nope"));
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let mut store = test_store();
        store.insert_from_config("MyApp", 3000, vec![]);
        assert!(store.lookup("myapp").is_some());
        assert!(store.lookup("MYAPP").is_some());
    }
}
