extern crate rsa;


use std::vec::Vec;

use rsa::{BigUint, RSAPublicKey, PublicKey};
use sha2::{Sha256, Digest};

use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

const DEFALT_SIZE: usize = 256;


pub trait EJPubKey {
    fn encrypt(&self, message: String) -> String;
    fn dencrypt(&self, message: String) -> String;
}

pub struct RandomStrings {
    alpha: String,
    beta: String
}

#[derive(Clone)]
pub struct BlindedDigest {
    m: Vec<BigUint>
}

#[derive(Clone)]
pub struct Unblinder {
    r: Vec<BigUint>
}

#[derive(Clone)]
pub struct EncryptedTraceInfo {
    u: Vec<String>
}

pub struct FBSParameters<EJ: EJPubKey> {
    judge_pubkey: EJ,
    signer_pubkey: RSAPublicKey,
    k: u32
}

pub struct FBSSender<EJ: EJPubKey> {
    parameters: FBSParameters<EJ>,
    random_strings: Option<RandomStrings>,
    blinded_digest: Option<BlindedDigest>,
    unblinder: Option<Unblinder>,
    trace_info: Option<EncryptedTraceInfo>,
    id: u32
}

fn generate_random_ubigint(size: usize) -> BigUint {
    let size = size / 32; 
    let random_bytes: Vec<u32> = (0..size).map(|_| { rand::random::<u32>() }).collect();
    return BigUint::new(random_bytes);
}

fn generate_random_string(len: usize) -> String {
    return thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .collect();
}

#[test]
fn test_generate_random_ubigint() {
    for i in 1..20 {
        let size = i * 64;
        let random = generate_random_ubigint(size);
        println!("{:x}\n\n\n", random);        
    }
}

#[test]
fn test_generate_random_string() {
    for len in 1..20 {
        let random = generate_random_string(len);
        println!("{}\n\n", random);
    }
}

