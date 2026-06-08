use serde::{Serialize, Serializer};

/// 所有 #[tauri::command] 回傳的統一錯誤型別。
/// 序列化成「訊息字串」，讓前端 invoke() 的 promise 以可讀字串 reject。
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("path is not allowed: {0}")]
    ForbiddenPath(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("{0}")]
    Other(String),

    #[error("parse error at line {line}: {msg}")]
    Parse { msg: String, line: usize },

    /// The on-disk file changed (or vanished) since it was loaded; refuse to overwrite so the
    /// front end can prompt the user to reload rather than clobber concurrent external edits.
    #[error("file changed on disk since it was loaded: {0}")]
    Conflict(String),
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_error_serializes_to_its_message() {
        let e = AppError::Other("boom".into());
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, "\"boom\"");
    }

    #[test]
    fn io_error_converts_and_serializes() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let e: AppError = io.into();
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, "\"io error: missing\"");
    }

    #[test]
    fn parse_error_serializes_to_its_message() {
        let e = AppError::Parse {
            msg: "bad".into(),
            line: 3,
        };
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, "\"parse error at line 3: bad\"");
    }
}
