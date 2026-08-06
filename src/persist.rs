//! Tiny JSON-file persistence helpers shared by the stores that mirror a
//! config layer to disk (`service_store`, `domain_list`). Read/write only —
//! each store owns its own config-vs-user merge policy. Best-effort: a missing
//! or corrupt file logs and yields an empty load rather than aborting startup.

use std::io::Write;
use std::path::Path;

use log::warn;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Load a `Vec<T>` from a JSON file, or an empty vec if the file is absent,
/// unreadable, or unparseable (the latter two are logged).
pub fn load_json_vec<T: DeserializeOwned>(path: &Path) -> Vec<T> {
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|e| {
            warn!("failed to parse {path:?}: {e}");
            Vec::new()
        }),
        Err(e) => {
            warn!("failed to read {path:?}: {e}");
            Vec::new()
        }
    }
}

/// Serialize `value` as pretty JSON to `path`, creating parent dirs. Written
/// via temp file + rename so a crash mid-write never truncates the previous
/// contents. Failures are logged, not propagated.
pub fn save_json<T: Serialize>(path: &Path, value: &T) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(value) {
        Ok(json) => {
            if let Err(e) = write_atomic(path, &json) {
                warn!("failed to write {path:?}: {e}");
            }
        }
        Err(e) => warn!("failed to serialize {path:?}: {e}"),
    }
}

/// Same durability as `save_json`, for payloads that are not JSON.
pub fn save_text(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = write_atomic(path, contents) {
        warn!("failed to write {path:?}: {e}");
    }
}

fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    // Appended, not `with_extension`, so a non-JSON payload keeps its own
    // extension and two files in the same dir cannot collide on the temp name.
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}
