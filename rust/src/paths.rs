//! Lossless Unix paths in persisted records and IPC. Ordinary UTF-8 paths stay
//! readable JSON strings; other names use an explicit byte representation.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Value {
    Text(String),
    Bytes { unix_bytes: Vec<u8> },
}
impl From<&Path> for Value {
    fn from(path: &Path) -> Self {
        path.to_str()
            .map(|p| Self::Text(p.into()))
            .unwrap_or_else(|| Self::Bytes {
                unix_bytes: path.as_os_str().as_bytes().to_vec(),
            })
    }
}
impl Value {
    fn path<E: serde::de::Error>(self) -> Result<PathBuf, E> {
        let raw = match self {
            Self::Text(s) => s.into_bytes(),
            Self::Bytes { unix_bytes } => unix_bytes,
        };
        if raw.contains(&0) {
            return Err(E::custom("Path contains a NUL byte"));
        }
        Ok(std::ffi::OsString::from_vec(raw).into())
    }
}
pub fn serialize<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    Value::from(path).serialize(serializer)
}
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
    Value::deserialize(deserializer)?.path()
}
pub mod optional {
    use super::*;
    pub fn serialize<S: Serializer>(
        path: &Option<PathBuf>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        path.as_deref().map(Value::from).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<PathBuf>, D::Error> {
        Option::<Value>::deserialize(deserializer)?
            .map(Value::path)
            .transpose()
    }
}
pub mod list {
    use super::*;
    pub fn serialize<S: Serializer>(paths: &[PathBuf], serializer: S) -> Result<S::Ok, S::Error> {
        paths
            .iter()
            .map(|p| Value::from(p.as_path()))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<PathBuf>, D::Error> {
        Vec::<Value>::deserialize(deserializer)?
            .into_iter()
            .map(Value::path)
            .collect()
    }
}
