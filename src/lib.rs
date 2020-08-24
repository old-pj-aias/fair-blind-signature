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


impl <EJ: EJPubKey>FBSSender<EJ> {
    pub fn new(id: u32, parameters: FBSParameters<EJ>) -> FBSSender<EJ>{
        let parameters = parameters;
        let id = id;

        let len = 2 * parameters.k;

        let random_strings = Some(RandomStrings {
            alpha: generate_random_string(len as usize),
            beta:  generate_random_string(len as usize)
        });

        FBSSender { 
            parameters: parameters,
            random_strings: random_strings,
            blinded_digest: None,
            unblinder: None,
            trace_info: None,
            id: id
        }
    }
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

struct TestCipherPubkey {}

impl EJPubKey for TestCipherPubkey {
    fn encrypt(&self, message: String) -> String {
        return message;
    }

    fn dencrypt(&self, message: String) -> String {
        return message;
    }
}


#[test]
fn test_signer_new() {
    let n = BigUint::from(187 as u32);
    let e = BigUint::from(7 as u32);
    
    let signer_pubkey = RSAPublicKey::new(n, e).unwrap();
    let judge_pubkey = TestCipherPubkey {};

    let parameters = FBSParameters {
        signer_pubkey: signer_pubkey,
        judge_pubkey: judge_pubkey,
        k: 40
    };

    let sender = FBSSender::new(10, parameters);
    assert_eq!(sender.id, 10);

    let random_strings = match sender.random_strings {
        Some(random_strings) => random_strings,
        None => {
            assert_eq!(true, false);
            return;
        }
    };


    println!("alpha: {}\nbeta: {}\n\n", random_strings.alpha, random_strings.beta);
}