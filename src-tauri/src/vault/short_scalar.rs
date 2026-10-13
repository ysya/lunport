//! Puts back the leading zero bytes OpenSSH leaves out of an ECDSA private scalar. OpenSSH writes the scalar as an mpint, in its shortest
//! form: leading zero bytes are dropped, and a 0x00 goes in front when the first byte left has its top bit set. `ssh-key` 0.6.7's
//! `EcdsaPrivateKey::decode` takes exactly 32/48/66 bytes (or one more, when that first byte is 0x00), so a scalar that comes out shorter
//! fails with `length invalid`, and `material::open` answered `Unreadable`. A scalar comes out shorter when its first byte is zero and the
//! next one has its top bit clear (with that bit set, the 0x00 in front makes up the length again): about 1 key in 512 that
//! `ssh-keygen -t ecdsa` makes for P-256 and P-384 (1/256 × 1/2), and 1 in 4 for P-521 (1/2 × 1/2: the first of its 66 bytes holds only
//! the top one of the 521 bits, so it is zero for half the keys; every scalar below 2^519 comes out short).
//!
//! When `ssh-key` cannot read a key, this module takes the `openssh-key-v1` container apart, pads the scalar to the curve's size,
//! recomputes the padding and hands an unencrypted container back to `ssh-key`, which still checks the checkints, that the public key
//! outside matches the point stored in the private section, the comment and the padding. Nothing checks that the scalar belongs to that
//! point (`ssh-key` does not for the keys it reads itself either): a key whose scalar is damaged opens, and its signatures do not verify.
//! An encrypted key has to be decrypted before its scalar can be seen, so `decrypt` decrypts it itself with `ssh-key`'s public `Kdf` and
//! `Cipher`, and goes on the same way.
//!
//! ssh-key 0.7.0-rc.11's `EcdsaPrivateKey::decode` pads the scalar, but not below 32 bytes, so a P-256 scalar one byte short still fails;
//! 0.7 is a pre-release too (ssh-encoding 0.3, rsa 0.10 rc), and the whole app relies on ssh-key for public keys and fingerprints, so it is
//! not upgraded: the scalar is padded here.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ssh_encoding::{Decode, Encode, Reader as _};
use ssh_key::public::KeyData;
use ssh_key::{Cipher, Kdf, PrivateKey};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"openssh-key-v1\0";
/// The begin and end lines (written in pieces, as in `test_keys`, so that a tool that scans for private keys does not take the source
/// for one).
const BEGIN: &str = concat!("-----BEGIN ", "OPENSSH", " PRIVATE KEY-----");
const END: &str = concat!("-----END ", "OPENSSH", " PRIVATE KEY-----");

// Test seam (test builds only, and only for the current thread): how many times `decrypt` derived a key from a passphrase, that is, ran
// bcrypt. A test counts with it that `material::open` does not try a wrong passphrase twice.
#[cfg(test)]
thread_local! {
    pub(crate) static KEY_DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The fixed length of each curve's scalar (`ssh-key`'s `EcdsaPrivateKey<SIZE>`).
fn scalar_size(algorithm: &str, curve: &str) -> Option<usize> {
    match (algorithm, curve) {
        ("ecdsa-sha2-nistp256", "nistp256") => Some(32),
        ("ecdsa-sha2-nistp384", "nistp384") => Some(48),
        ("ecdsa-sha2-nistp521", "nistp521") => Some(66),
        _ => None,
    }
}

/// An `openssh-key-v1` container taken apart (one key).
struct Container {
    cipher: Cipher,
    kdf: Kdf,
    /// The contents of the public key section.
    public: Vec<u8>,
    /// The contents of the private section: plaintext when the key is not encrypted, ciphertext when it is.
    private: Zeroizing<Vec<u8>>,
    /// The tag an AEAD cipher (`*-gcm@openssh.com`, chacha20-poly1305) puts after the ciphertext.
    tag: Option<[u8; 16]>,
}

/// The private key text taken apart into its container: the base64 between the begin and end lines, then each field of the format. A
/// malformed one (several keys, text after the end line, a private section that is not a whole number of the cipher's blocks…) gives None.
fn container(private_key: &str) -> Option<Container> {
    let mut lines = private_key.lines().map(str::trim).filter(|line| !line.is_empty());
    if lines.next()? != BEGIN {
        return None;
    }
    // For a key without a passphrase this base64 is the whole private key: it is wiped when dropped, and it has room for all of the text
    // from the start, so it never moves (a String that grows leaves the block it moved out of behind, unwiped).
    let mut body = Zeroizing::new(String::with_capacity(private_key.len()));
    let mut ended = false;
    for line in lines {
        if ended {
            return None;
        }
        if line == END {
            ended = true;
        } else {
            body.push_str(line);
        }
    }
    if !ended {
        return None;
    }
    // Decoded into a buffer of our own, which is wiped also when the base64 turns out bad halfway through.
    let mut bytes = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(body.len())]);
    let len = STANDARD.decode_slice(body.as_bytes(), &mut bytes[..]).ok()?;
    bytes.truncate(len);
    let mut reader = &bytes[..];
    let mut magic = [0u8; MAGIC.len()];
    reader.read(&mut magic).ok()?;
    if magic != MAGIC {
        return None;
    }
    let cipher = Cipher::decode(&mut reader).ok()?;
    let kdf = Kdf::decode(&mut reader).ok()?;
    if u32::decode(&mut reader).ok()? != 1 {
        return None;
    }
    let public = Vec::<u8>::decode(&mut reader).ok()?;
    let private = Zeroizing::new(Vec::<u8>::decode(&mut reader).ok()?);
    // `ssh-key` refuses a private section that is not a whole number of blocks (an encrypted one already when it parses the key, before
    // any passphrase is tried).
    if private.len() % cipher.block_size() != 0 {
        return None;
    }
    let tag = if cipher.has_tag() {
        let mut tag = [0u8; 16];
        reader.read(&mut tag).ok()?;
        Some(tag)
    } else {
        None
    };
    reader.is_finished().then_some(Container { cipher, kdf, public, private, tag })
}

/// The plaintext of a private section (`checkint ×2, string algorithm, string curve, string point, mpint scalar, string comment,
/// padding`) whose ECDSA scalar is shorter than the curve's size: a new section, the scalar padded with zeros and the padding recomputed
/// for an unencrypted container (a multiple of 8). Not ECDSA, a scalar of normal length (one `ssh-key` reads itself, or one really too
/// long), a negative one or a malformed section all give None. `block_size` is the original container's: the padding has to be
/// `1, 2, 3…` and shorter than one block (the checks `ssh-key` makes on it).
fn repadded(section: &[u8], block_size: usize) -> Option<Zeroizing<Vec<u8>>> {
    let mut reader = section;
    let checkint1 = u32::decode(&mut reader).ok()?;
    let checkint2 = u32::decode(&mut reader).ok()?;
    let algorithm = String::decode(&mut reader).ok()?;
    let curve = String::decode(&mut reader).ok()?;
    let size = scalar_size(&algorithm, &curve)?;
    let point = Vec::<u8>::decode(&mut reader).ok()?;
    let scalar = Zeroizing::new(Vec::<u8>::decode(&mut reader).ok()?);
    let comment = String::decode(&mut reader).ok()?;
    let padding_is_valid = reader.len() < block_size && reader.iter().zip(1u8..).all(|(byte, expected)| *byte == expected);
    // An mpint whose first byte has its top bit set is negative: OpenSSH refuses to read one, and writes a 0x00 in front of such a scalar.
    let negative = scalar.first().is_some_and(|byte| byte & 0x80 != 0);
    if !padding_is_valid || negative || scalar.len() >= size {
        return None;
    }

    let mut padded = Zeroizing::new(vec![0u8; size]);
    padded[size - scalar.len()..].copy_from_slice(&scalar);
    // Room for the whole new section from the start (the old one, the scalar at most `size` bytes longer, under 8 bytes of padding): a Vec
    // that grows leaves the block it moved out of behind, unwiped, and the scalar would be in it.
    let mut out = Zeroizing::new(Vec::with_capacity(section.len() + size + 8));
    checkint1.encode(&mut *out).ok()?;
    checkint2.encode(&mut *out).ok()?;
    algorithm.encode(&mut *out).ok()?;
    curve.encode(&mut *out).ok()?;
    point.encode(&mut *out).ok()?;
    padded.encode(&mut *out).ok()?;
    comment.encode(&mut *out).ok()?;
    let mut pad = 1u8;
    while out.len() % Cipher::None.block_size() != 0 {
        out.push(pad);
        pad += 1;
    }
    Some(out)
}

/// Puts the padded private section and the original public section back into an unencrypted `openssh-key-v1` container, and has
/// `ssh-key` read it.
fn read_unencrypted(public: &[u8], section: &[u8]) -> Option<PrivateKey> {
    let mut bytes = Zeroizing::new(MAGIC.to_vec());
    Cipher::None.encode(&mut *bytes).ok()?;
    Kdf::None.encode(&mut *bytes).ok()?;
    1u32.encode(&mut *bytes).ok()?;
    public.encode(&mut *bytes).ok()?;
    section.encode(&mut *bytes).ok()?;
    PrivateKey::from_bytes(&bytes).ok()
}

/// Private key text `ssh-key` cannot read: an unencrypted ECDSA key whose scalar is short is read again with the scalar padded. Anything
/// else (an encrypted key, not ECDSA, a scalar of normal length, a malformed key) gives None, so that the caller keeps its own error.
pub fn parse(private_key: &str) -> Option<PrivateKey> {
    let container = container(private_key)?;
    // An unencrypted key that names a KDF is one `ssh-key` refuses.
    if container.cipher.is_some() || container.kdf.is_some() {
        return None;
    }
    let section = repadded(&container.private, Cipher::None.block_size())?;
    read_unencrypted(&container.public, &section)
}

/// An encrypted private key that `ssh-key` refused with this passphrase for the length of a field, which is what it does with the right
/// passphrase and a short scalar (`material::open` comes here only then): an ECDSA key is decrypted here, with `ssh-key`'s public `Kdf`
/// and `Cipher`, and read again with the scalar padded. A wrong passphrase (what comes out is not a private section), a key that is not
/// encrypted, not ECDSA (seen in the public section, before any bcrypt) or whose scalar has its normal length all give None.
pub fn decrypt(private_key: &str, passphrase: &str) -> Option<PrivateKey> {
    let container = container(private_key)?;
    if container.cipher.is_none() || !KeyData::decode(&mut &container.public[..]).is_ok_and(|key| key.is_ecdsa()) {
        return None;
    }
    #[cfg(test)]
    KEY_DERIVATIONS.with(|count| count.set(count.get() + 1));
    let (key, iv) = container.kdf.derive_key_and_iv(container.cipher, passphrase).ok()?;
    let mut plaintext = container.private;
    container.cipher.decrypt(&key, &iv, &mut plaintext, container.tag).ok()?;
    let section = repadded(&plaintext, container.cipher.block_size())?;
    read_unencrypted(&container.public, &section)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys::{self, EcdsaSection};

    /// The length of the scalar as the key's text has it (a test key's scalar has to be short there, or the test is not about this).
    fn scalar_len(private_key: &str) -> usize {
        let container = container(private_key).unwrap();
        let mut reader = &container.private[..];
        for _ in 0..2 {
            u32::decode(&mut reader).unwrap();
        }
        for _ in 0..3 {
            Vec::<u8>::decode(&mut reader).unwrap();
        }
        Vec::<u8>::decode(&mut reader).unwrap().len()
    }

    #[test]
    fn a_short_scalar_is_padded_to_the_curve_and_the_rest_of_the_key_is_kept() {
        for (what, private, public, short, size) in [
            ("p256", test_keys::ecdsa_short_p256(), test_keys::ECDSA_SHORT_P256_PUBLIC, 31, 32),
            ("p384", test_keys::ecdsa_short_p384(), test_keys::ECDSA_SHORT_P384_PUBLIC, 47, 48),
            ("p521", test_keys::ecdsa_short_p521(), test_keys::ECDSA_SHORT_P521_PUBLIC, 65, 66),
        ] {
            assert_eq!(scalar_len(&private), short, "{what}: setup: the scalar lost a leading zero");
            assert!(PrivateKey::from_openssh(&private).is_err(), "{what}: setup: ssh-key 0.6.7 alone can't read it");
            let key = parse(&private).unwrap_or_else(|| panic!("{what}"));
            assert_eq!(key.public_key().key_data(), &ssh_key::PublicKey::from_openssh(public).unwrap().key_data().clone(), "{what}");
            let ssh_key::private::KeypairData::Ecdsa(keypair) = key.key_data() else { panic!("{what}: ecdsa") };
            let scalar = match keypair {
                ssh_key::private::EcdsaKeypair::NistP256 { private, .. } => private.as_slice().to_vec(),
                ssh_key::private::EcdsaKeypair::NistP384 { private, .. } => private.as_slice().to_vec(),
                ssh_key::private::EcdsaKeypair::NistP521 { private, .. } => private.as_slice().to_vec(),
            };
            assert_eq!(scalar.len(), size, "{what}");
            assert_eq!(scalar[0], 0, "{what}: the leading zero is back");
        }
        assert_eq!(parse(&test_keys::ecdsa_short_p256()).unwrap().comment(), "scratch-short-256");
    }

    #[test]
    fn keys_ssh_key_reads_or_rejects_for_other_reasons_are_left_alone() {
        assert!(parse(&test_keys::ecdsa()).is_none(), "a full-length scalar is ssh-key's to read");
        assert!(parse(&test_keys::plain()).is_none(), "not ECDSA");
        assert!(parse(&test_keys::rsa()).is_none(), "not ECDSA");
        assert!(parse(&test_keys::ecdsa_short_p256_encrypted()).is_none(), "encrypted: `decrypt` is the way in");
        assert!(parse("not a key").is_none());
        assert!(parse(&format!("{}\ntrailing", test_keys::ecdsa_short_p256())).is_none(), "text after the end line");
        assert!(parse(&test_keys::ecdsa_short_p256().replace("OPENSSH PRIVATE", "EC PRIVATE")).is_none());
    }

    #[test]
    fn an_encrypted_short_scalar_opens_with_the_right_passphrase_only() {
        let text = test_keys::ecdsa_short_p256_encrypted();
        assert_eq!(PrivateKey::from_openssh(&text).unwrap().decrypt("test-passphrase").err(), Some(ssh_key::Error::Encoding(ssh_encoding::Error::Length)), "setup: ssh-key 0.6.7 can't decrypt it");
        let key = decrypt(&text, "test-passphrase").unwrap();
        assert_eq!(key.public_key().key_data(), &ssh_key::PublicKey::from_openssh(test_keys::ECDSA_SHORT_P256_PUBLIC).unwrap().key_data().clone());
        assert!(!key.is_encrypted());
        assert!(decrypt(&text, "wrong").is_none());
        assert!(decrypt(&test_keys::ecdsa_short_p256(), "test-passphrase").is_none(), "not encrypted");
        assert!(decrypt(&test_keys::encrypted(), "test-passphrase").is_none(), "not ECDSA");
    }

    /// What `ssh-key` refuses in a container whose scalar has its full length is refused with a short one too: an unencrypted key that
    /// names a KDF, a private section that is not a whole number of blocks, and a negative scalar (OpenSSH refuses an mpint whose top bit
    /// is set).
    #[test]
    fn a_short_scalar_does_not_make_a_container_ssh_key_refuses_readable() {
        let bcrypt = test_keys::one_round_bcrypt();

        let (public, section) = EcdsaSection::of(test_keys::ECDSA_SHORT_P256_BODY);
        let full = section.with_full_scalar(32);
        assert_eq!(PrivateKey::from_openssh(test_keys::openssh_key(Cipher::None, &bcrypt, &public, &full.padded(8), "")).err(), Some(ssh_key::Error::Crypto), "setup: ssh-key refuses an unencrypted key that names a KDF");
        assert!(parse(&test_keys::openssh_key(Cipher::None, &Kdf::None, &public, &section.padded(8), "")).is_some(), "setup: without the KDF the key is read");
        assert!(parse(&test_keys::openssh_key(Cipher::None, &bcrypt, &public, &section.padded(8), "")).is_none(), "an unencrypted key that names a KDF");

        let mut negative = section.clone();
        negative.scalar[0] |= 0x80;
        assert!(parse(&test_keys::openssh_key(Cipher::None, &Kdf::None, &public, &negative.padded(8), "")).is_none(), "a negative scalar");

        // P-521's private section comes to 262 bytes without its padding.
        let (public, section) = EcdsaSection::of(test_keys::ECDSA_SHORT_P521_BODY);
        let full = section.with_full_scalar(66);
        assert_ne!(full.with_padding(&[]).len() % 8, 0, "setup");
        assert_eq!(PrivateKey::from_openssh(test_keys::openssh_key(Cipher::None, &Kdf::None, &public, &full.with_padding(&[]), "")).err(), Some(ssh_key::Error::Encoding(ssh_encoding::Error::Length)), "setup: ssh-key refuses a section that is not a whole number of blocks");
        assert!(parse(&test_keys::openssh_key(Cipher::None, &Kdf::None, &public, &section.with_padding(&[]), "")).is_none(), "an unencrypted section that is not a whole number of blocks");
        let encrypted = test_keys::openssh_key(Cipher::Aes256Ctr, &bcrypt, &public, &section.with_padding(&[]), "pass");
        assert_eq!(PrivateKey::from_openssh(&encrypted).err(), Some(ssh_key::Error::Crypto), "setup: ssh-key refuses such a ciphertext before any passphrase");
        assert!(decrypt(&encrypted, "pass").is_none(), "a ciphertext that is not a whole number of blocks");
        assert!(decrypt(&test_keys::openssh_key(Cipher::Aes256Ctr, &bcrypt, &public, &section.padded(16), "pass"), "pass").is_some(), "setup: padded, it opens");
    }
}
