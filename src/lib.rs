pub mod buffer;
pub mod cache;
pub mod config;
pub mod forward;
pub mod header;
pub mod packet;
pub mod question;
pub mod record;
pub mod stats;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
