use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("parser '{parser}' failed at offset {offset}: {source}")]
    Parse {
        parser: &'static str,
        offset: u64,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("detector '{detector}' failed: {source}")]
    Detector {
        detector: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("memory ceiling exceeded: used {used} bytes, limit {limit} bytes")]
    MemoryExceeded { used: usize, limit: usize },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sandbox initialization failed: {0}")]
    Sandbox(String),

    #[error("operation cancelled")]
    Cancelled,

    #[error("config error: {0}")]
    Config(String),
}
