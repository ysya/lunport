//! Compact explicit local archive encoding. Decoding never writes a filesystem path.
use super::*;
const MAGIC: &[u8; 8] = b"LPFILES1";
const MAX_PATH: usize = 256 * (MAX_DEPTH + 2);
pub(in crate::sync::central) const MAX_ENCODED: usize =
    MAX_TOTAL_BYTES as usize + MAX_ENTRIES * (MAX_PATH + 12) + 16;
fn path(value: &str, directory: bool) -> Result<PathBuf, AppError> {
    let parts: Vec<_> = value.split('/').collect();
    if value.len() > MAX_PATH
        || parts.len() > MAX_DEPTH + 2
        || parts.iter().any(|v| !single_name(v))
        || !matches!(parts[0], "data" | "keys")
        || parts.len() == 1 && !directory
        || parts[0] == "data"
            && (parts.len() > 2 || directory && parts.len() > 1)
            && !matches!(
                parts[1],
                "imports" | "migrations" | "central-recovery-archives" | "central-source-archives"
            )
    {
        return Err(invalid());
    }
    Ok(parts.iter().collect())
}
fn encoded_path(value: &Path, directory: bool) -> Result<&str, AppError> {
    let value_str = value.to_str().ok_or_else(invalid)?;
    if path(value_str, directory)? != value {
        return Err(invalid());
    }
    Ok(value_str)
}
fn parent_present(value: &Path, dirs: &BTreeSet<PathBuf>) -> bool {
    value
        .parent()
        .is_none_or(|v| v.as_os_str().is_empty() || dirs.contains(v))
}
impl Files {
    pub(in crate::sync::central) fn validate_archive(&self) -> Result<usize, AppError> {
        if self.entries != self.directories.len() + self.bytes.len() || self.entries > MAX_ENTRIES {
            return Err(invalid());
        }
        let mut encoded = 16usize;
        for directory in &self.directories {
            let name = encoded_path(directory, true)?;
            if self.bytes.contains_key(directory) || !parent_present(directory, &self.directories) {
                return Err(invalid());
            }
            encoded += 4 + name.len();
        }
        let mut total = 0u64;
        for (file, bytes) in &self.bytes {
            let name = encoded_path(file, false)?;
            if !parent_present(file, &self.directories) || bytes.len() as u64 > MAX_FILE_BYTES {
                return Err(invalid());
            }
            total = total.checked_add(bytes.len() as u64).ok_or_else(invalid)?;
            if total > MAX_TOTAL_BYTES {
                return Err(invalid());
            }
            encoded += 12 + name.len() + bytes.len();
        }
        if total != self.total || encoded > MAX_ENCODED {
            return Err(invalid());
        }
        Ok(encoded)
    }
    pub fn encode_local(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let length = self.validate_archive()?;
        let mut out = Zeroizing::new(Vec::with_capacity(length));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.directories.len() as u32).to_be_bytes());
        for directory in &self.directories {
            write_path(&mut out, encoded_path(directory, true)?);
        }
        out.extend_from_slice(&(self.bytes.len() as u32).to_be_bytes());
        for (file, bytes) in &self.bytes {
            write_path(&mut out, encoded_path(file, false)?);
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        debug_assert_eq!(out.len(), length);
        Ok(out)
    }
    pub fn decode_local(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() > MAX_ENCODED {
            return Err(invalid());
        }
        let mut input = Input(bytes);
        if input.take(8)? != MAGIC {
            return Err(invalid());
        }
        let count = input.u32()?;
        if count > MAX_ENTRIES {
            return Err(invalid());
        }
        let mut result = Self {
            bytes: BTreeMap::new(),
            directories: BTreeSet::new(),
            total: 0,
            entries: 0,
        };
        let mut previous = None;
        for _ in 0..count {
            let directory = input.path(true)?;
            if previous.as_ref().is_some_and(|v| v >= &directory) {
                return Err(invalid());
            }
            previous = Some(directory.clone());
            result.directories.insert(directory);
        }
        let count = input.u32()?;
        if count > MAX_ENTRIES - result.directories.len() {
            return Err(invalid());
        }
        previous = None;
        for _ in 0..count {
            let file = input.path(false)?;
            if previous.as_ref().is_some_and(|v| v >= &file) {
                return Err(invalid());
            }
            let length = input.u64()?;
            if length > MAX_FILE_BYTES || length > MAX_TOTAL_BYTES - result.total {
                return Err(invalid());
            }
            let bytes = Zeroizing::new(input.take(length as usize)?.to_vec());
            result.total += length;
            previous = Some(file.clone());
            result.bytes.insert(file, bytes);
        }
        result.entries = result.directories.len() + result.bytes.len();
        if !input.0.is_empty() {
            return Err(invalid());
        }
        result.validate_archive()?;
        Ok(result)
    }
}
fn write_path(out: &mut Vec<u8>, path: &str) {
    out.extend_from_slice(&(path.len() as u32).to_be_bytes());
    out.extend_from_slice(path.as_bytes());
}
struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], AppError> {
        if length > self.0.len() {
            return Err(invalid());
        }
        let (value, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(value)
    }
    fn u32(&mut self) -> Result<usize, AppError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| invalid())?) as usize)
    }
    fn u64(&mut self) -> Result<u64, AppError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| invalid())?,
        ))
    }
    fn path(&mut self, directory: bool) -> Result<PathBuf, AppError> {
        let length = self.u32()?;
        if length > MAX_PATH {
            return Err(invalid());
        }
        path(
            std::str::from_utf8(self.take(length)?).map_err(|_| invalid())?,
            directory,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(dirs: &[&str], files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&(dirs.len() as u32).to_be_bytes());
        for value in dirs {
            write_path(&mut out, value);
        }
        out.extend_from_slice(&(files.len() as u32).to_be_bytes());
        for (file, value) in files {
            write_path(&mut out, file);
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(value);
        }
        out
    }
    #[test]
    fn compact_archive_roundtrip_preserves_binary_private_bytes_and_empty_directories() {
        let original = bytes(
            &["data", "data/imports", "data/imports/empty", "keys"],
            &[
                ("data/sync-state.json", b"original\0\xff\n"),
                ("keys/private", b"-----PRIVATE SOURCE-----\r\n"),
                ("keys/zero", b""),
            ],
        );
        let files = Files::decode_local(&original).unwrap();
        assert!(files.directories.contains(Path::new("data/imports/empty")));
        assert_eq!(
            files.bytes[Path::new("data/sync-state.json")].as_slice(),
            b"original\0\xff\n"
        );
        assert_eq!(files.encode_local().unwrap().as_slice(), original);
        for length in 0..original.len() {
            assert!(
                Files::decode_local(&original[..length]).is_err(),
                "{length}"
            );
        }
        let mut extra = original.clone();
        extra.push(0);
        assert!(Files::decode_local(&extra).is_err());
        let mut version = original;
        version[7] = b'2';
        assert!(Files::decode_local(&version).is_err());
        assert_eq!(Files::decode_local(&bytes(&[], &[])).unwrap().entries, 0);
    }
    #[test]
    fn invalid_categories_traversal_missing_parents_duplicate_paths_and_collisions_are_rejected() {
        for bad in [
            "/data/file",
            "data/../escape",
            "data//file",
            "data/./file",
            "data/file/",
            "data/file\\escape",
            "data/a\0b",
            "outside/file",
            "keys",
            "data/arbitrary/deep",
            "keys/missing/file",
        ] {
            assert!(
                Files::decode_local(&bytes(&["data", "keys"], &[(bad, b"private")])).is_err(),
                "{bad:?}"
            );
        }
        for dirs in [
            vec!["data", "data"],
            vec!["keys", "data"],
            vec!["data", "data/unknown"],
            vec!["data", "data/imports/missing"],
            vec!["data", "data/imports/../escape"],
        ] {
            assert!(Files::decode_local(&bytes(&dirs, &[])).is_err());
        }
        assert!(Files::decode_local(&bytes(
            &["data", "data/imports"],
            &[("data/imports", b"collision")]
        ))
        .is_err());
        for names in [["keys/a", "keys/a"], ["keys/b", "keys/a"]] {
            assert!(
                Files::decode_local(&bytes(&["keys"], &[(names[0], b"a"), (names[1], b"b")]))
                    .is_err()
            );
        }
    }
    #[test]
    fn count_path_depth_length_and_in_memory_consistency_bounds_fail_before_returning_a_partial_set(
    ) {
        let mut count = MAGIC.to_vec();
        count.extend_from_slice(&((MAX_ENTRIES + 1) as u32).to_be_bytes());
        assert!(Files::decode_local(&count).is_err());
        let mut length = bytes(&["keys"], &[("keys/a", b"")]);
        let end = length.len();
        length[end - 8..].copy_from_slice(&(MAX_FILE_BYTES + 1).to_be_bytes());
        assert!(Files::decode_local(&length).is_err());
        let too_long = format!("keys/{}", "a".repeat(256));
        assert!(Files::decode_local(&bytes(&["keys"], &[(&too_long, b"")])).is_err());
        let too_deep = format!("keys/{}", vec!["child"; MAX_DEPTH + 2].join("/"));
        assert!(path(&too_deep, true).is_err());
        let mut files = Files::decode_local(&bytes(&["keys"], &[("keys/a", b"a")])).unwrap();
        files.total += 1;
        assert!(files.encode_local().is_err());
        files.total -= 1;
        files.entries += 1;
        assert!(files.encode_local().is_err());
        files.entries -= 1;
        files.directories.clear();
        files.entries -= 1;
        assert!(files.encode_local().is_err());
    }
}
