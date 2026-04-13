//! sanitai-store: append-only SQLite-backed scan history store.
//!
//! Every `sanitai scan` invocation appends one [`ScanRecord`] (plus associated
//! [`FindingRecord`]s) so that analytics and history UIs have durable data to
//! query.  The store is intentionally single-file and requires no server.

pub mod error;
pub mod models;
pub mod schema;
pub mod store;

pub use error::StoreError;
pub use models::{FindingRecord, ScanRecord};
pub use store::{Store, StoreTotals};
