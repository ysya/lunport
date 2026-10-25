//! OS Login's login profile (`oslogin.googleapis.com` v1): the POSIX accounts and SSH public keys Google keeps for a Google account. The
//! REST calls live in `gcp::rest`; this is the data and the two questions the broker asks of it: which username, and is this key there.

use super::rest::GcpError;

/// One POSIX account of a login profile (`PosixAccount` in the API; the fields the broker reads).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PosixAccount {
    pub username: String,
    /// The account OS Login uses by default.
    pub primary: bool,
    /// `LINUX`, `WINDOWS`, or unset (`OPERATING_SYSTEM_TYPE_UNSPECIFIED`, which counts as Linux).
    pub operating_system_type: Option<String>,
}

/// A Google account's OS Login profile.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginProfile {
    pub posix_accounts: Vec<PosixAccount>,
    /// The registered keys as OpenSSH public key lines (`<algorithm> <base64> [comment]`).
    pub ssh_public_keys: Vec<String>,
}

impl LoginProfile {
    /// The username to log in with: the primary account's, else the first Linux (or untyped) account's. `None` when the profile has no
    /// POSIX account for Linux, which is what a project without OS Login, or a brand-new identity, looks like.
    pub fn username(&self) -> Option<&str> {
        let linux = |account: &&PosixAccount| account.operating_system_type.as_deref().is_none_or(|kind| kind == "LINUX" || kind == "OPERATING_SYSTEM_TYPE_UNSPECIFIED");
        self.posix_accounts
            .iter()
            .find(|account| account.primary)
            .or_else(|| self.posix_accounts.iter().find(linux))
            .map(|account| account.username.as_str())
            .filter(|username| !username.is_empty())
    }

    /// Whether `line` (an OpenSSH public key line) is registered: same algorithm and same blob, whatever the comment.
    pub fn has_key(&self, line: &str) -> bool {
        let Some(wanted) = key_identity(line) else { return false };
        self.ssh_public_keys.iter().any(|registered| key_identity(registered) == Some(wanted.clone()))
    }
}

/// The algorithm and the base64 blob of an OpenSSH public key line, the two parts that identify a key; `None` for a line that is not one.
pub fn key_identity(line: &str) -> Option<(String, String)> {
    let mut parts = line.split_whitespace();
    let algorithm = parts.next()?;
    let blob = parts.next()?;
    (algorithm.contains('-') && !blob.is_empty()).then(|| (algorithm.to_string(), blob.to_string()))
}

/// A `LoginProfile` from the API's JSON (`GET users/{account}/loginProfile`, or the `loginProfile` of an import's answer).
pub fn parse_profile(value: &serde_json::Value) -> Result<LoginProfile, GcpError> {
    let object = value.as_object().ok_or_else(|| GcpError::Malformed("the login profile is not an object".to_string()))?;
    let text = |value: &serde_json::Value, name: &str| value.get(name).and_then(serde_json::Value::as_str).map(str::to_string);
    let posix_accounts = object
        .get("posixAccounts")
        .and_then(serde_json::Value::as_array)
        .map(|accounts| {
            accounts
                .iter()
                .map(|account| PosixAccount {
                    username: text(account, "username").unwrap_or_default(),
                    primary: account.get("primary").and_then(serde_json::Value::as_bool).unwrap_or(false),
                    operating_system_type: text(account, "operatingSystemType"),
                })
                .collect()
        })
        .unwrap_or_default();
    let ssh_public_keys = object
        .get("sshPublicKeys")
        .and_then(serde_json::Value::as_object)
        .map(|keys| keys.values().filter_map(|key| text(key, "key")).collect())
        .unwrap_or_default();
    Ok(LoginProfile { posix_accounts, ssh_public_keys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGvBwpCj0GQWLW0hG8bQ4qJ8r7ZcXx9x2nH0f0e3Q1aB";

    fn account(username: &str, primary: bool, os: Option<&str>) -> PosixAccount {
        PosixAccount { username: username.into(), primary, operating_system_type: os.map(str::to_string) }
    }

    #[test]
    fn the_username_is_the_primary_posix_account_else_the_first_linux_one() {
        let primary = LoginProfile { posix_accounts: vec![account("a", false, Some("LINUX")), account("b", true, Some("LINUX"))], ssh_public_keys: vec![] };
        assert_eq!(primary.username(), Some("b"));
        let linux = LoginProfile { posix_accounts: vec![account("w", false, Some("WINDOWS")), account("l", false, Some("LINUX"))], ssh_public_keys: vec![] };
        assert_eq!(linux.username(), Some("l"));
        let untyped = LoginProfile { posix_accounts: vec![account("x", false, None)], ssh_public_keys: vec![] };
        assert_eq!(untyped.username(), Some("x"));
        let none = LoginProfile { posix_accounts: vec![], ssh_public_keys: vec![] };
        assert_eq!(none.username(), None);
        let windows_only = LoginProfile { posix_accounts: vec![account("w", false, Some("WINDOWS"))], ssh_public_keys: vec![] };
        assert_eq!(windows_only.username(), None);
    }

    #[test]
    fn a_key_is_recognised_by_algorithm_and_blob_whatever_the_comment() {
        let profile = LoginProfile { posix_accounts: vec![], ssh_public_keys: vec![format!("{KEY} frank@laptop")] };
        assert!(profile.has_key(KEY));
        assert!(profile.has_key(&format!("{KEY} another comment\n")));
        assert!(!profile.has_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherBlobOtherBlobOtherBlobOtherBlobOtherBlob"));
        assert!(!profile.has_key("not a key"));
        assert_eq!(key_identity(&format!("{KEY} comment")), Some(("ssh-ed25519".to_string(), KEY.split(' ').nth(1).unwrap().to_string())));
        assert_eq!(key_identity("ssh-ed25519"), None);
        assert_eq!(key_identity(""), None);
    }

    #[test]
    fn a_profile_is_parsed_from_the_apis_json() {
        let json = json!({
            "name": "users/frank@example.com",
            "posixAccounts": [{
                "primary": true,
                "username": "frank_example_com",
                "uid": "1001",
                "gid": "1001",
                "homeDirectory": "/home/frank_example_com",
                "operatingSystemType": "LINUX",
                "accountId": "acme-dev-654321"
            }],
            "sshPublicKeys": {
                "3b2f": { "key": format!("{KEY} frank@laptop"), "fingerprint": "3b2f", "name": "users/frank@example.com/sshPublicKeys/3b2f" }
            }
        });
        let profile = parse_profile(&json).unwrap();
        assert_eq!(profile.username(), Some("frank_example_com"));
        assert_eq!(profile.posix_accounts[0].operating_system_type.as_deref(), Some("LINUX"));
        assert!(profile.has_key(KEY));
        let empty = parse_profile(&json!({"name": "users/frank@example.com"})).unwrap();
        assert_eq!((empty.username(), empty.ssh_public_keys.len()), (None, 0));
        assert!(parse_profile(&json!("not an object")).is_err());
    }
}
