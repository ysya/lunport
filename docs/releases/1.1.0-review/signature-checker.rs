use minisign_verify::{PublicKey, Signature};
use std::{env, fs};

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(args.len(), 4, "usage: checker public-key signature artifact");
    let key = PublicKey::decode(&fs::read_to_string(&args[1]).unwrap()).unwrap();
    let signature = Signature::decode(&fs::read_to_string(&args[2]).unwrap()).unwrap();
    let mut data = fs::read(&args[3]).unwrap();
    key.verify(&data, &signature, false).expect("artifact signature failed");
    assert!(!data.is_empty());
    data[0] ^= 1;
    assert!(key.verify(&data, &signature, false).is_err(), "tampered data accepted");
    println!("Signature verified; tampered copy rejected: {}", args[3]);
}
