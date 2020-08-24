extern crate rsa;


use std::vec::Vec;

use rsa::{BigUint, RSAPublicKey, PublicKey, RSAPrivateKey};
use sha2::{Sha256, Digest};

use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

const DEFALT_SIZE: usize = 256;


pub trait EJPubKey {
    fn encrypt(&self, message: String) -> String;
    fn dencrypt(&self, message: String) -> String;
}

#[derive(Clone)]
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

#[derive(Clone)]
pub struct FBSParameters<EJ: EJPubKey> {
    judge_pubkey: EJ,
    signer_pubkey: RSAPublicKey,
    k: u32,
    id: u32
}

pub struct FBSSender<EJ: EJPubKey> {
    parameters: FBSParameters<EJ>,
    random_strings: Option<RandomStrings>,
    blinded_digest: Option<BlindedDigest>,
    unblinder: Option<Unblinder>,
    trace_info: Option<EncryptedTraceInfo>,
}

pub struct Subset {
    subset: Vec<u32>,
    k: u32
}

pub struct CheckParameter {
    part_of_trace_info: EncryptedTraceInfo,
    part_of_unblinder: Unblinder,
    part_of_beta: Vec<String>
}

pub struct FBSSigner<EJ: EJPubKey> {
    parameters: FBSParameters<EJ>,
    blinded_digest: Option<BlindedDigest>,
    subset: Option<Subset>,
    check: Option<CheckParameter>,
    privkey: RSAPrivateKey
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


impl <EJ: EJPubKey>FBSSigner<EJ> {
    pub fn new(parameters: FBSParameters<EJ>, privkey: RSAPrivateKey) -> FBSSigner<EJ>{
        FBSSigner { 
            parameters: parameters,
            blinded_digest: None,
            check: None,
            subset: None,
            privkey: privkey
        }
    }
}

impl <EJ: EJPubKey>FBSSender<EJ> {
    pub fn new(parameters: FBSParameters<EJ>) -> FBSSender<EJ>{
        let parameters = parameters;

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
        }
    }

    pub fn blind(&mut self, message: String) -> Option<(BlindedDigest, Unblinder, EncryptedTraceInfo)> {
        let mut r = Vec::new();
        let mut u = Vec::new();
        let mut v = Vec::new();
        let mut m = Vec::new();

        let len = 2 * self.parameters.k;
        let alpha = self.random_strings.as_ref()?.alpha.as_bytes();
        let beta = self.random_strings.as_ref()?.beta.as_bytes();


        for i in 0..len {
            let r_i = generate_random_ubigint(DEFALT_SIZE);
            
            let u_i = format!("{}{}", message, alpha[i as usize]);
            let u_i = self.parameters.judge_pubkey.encrypt(u_i);
            
            let v_i = format!("{}{}", self.parameters.id, beta[i as usize]);
            let v_i = self.parameters.judge_pubkey.encrypt(v_i);

            let r_e_i = r_i.modpow(self.parameters.signer_pubkey.e(), self.parameters.signer_pubkey.n());

            let h_i = format!("{}{}", u_i, v_i);

            let mut hasher = Sha256::new();
            hasher.update(h_i);
            let h_i = hasher.finalize();
            let h_i = BigUint::from_bytes_le(&h_i);

            let m_i = r_e_i * h_i % self.parameters.signer_pubkey.n();

            r.push(r_i);
            u.push(u_i);
            v.push(v_i);
            m.push(m_i);
        }

        let blinded_digest = BlindedDigest { m: m };
        let unblinder = Unblinder { r: r };
        let trace_info = EncryptedTraceInfo { u: u };

        self.blinded_digest = Some(blinded_digest.clone());
        self.unblinder = Some(unblinder.clone());
        self.trace_info = Some(trace_info.clone());

        return Some((blinded_digest, unblinder, trace_info))
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

#[derive(Clone)]
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
fn test_signer_blind() {
    let n = BigUint::from(187 as u32);
    let e = BigUint::from(7 as u32);
    let d = BigUint::from(23 as u32);
    let primes = [BigUint::from(7 as u32), BigUint::from(11 as u32)].to_vec();
    
    let signer_pubkey = RSAPublicKey::new(n.clone(), e.clone()).unwrap();
    let judge_pubkey = TestCipherPubkey {};

    let parameters = FBSParameters {
        signer_pubkey: signer_pubkey,
        judge_pubkey: judge_pubkey,
        k: 40,
        id: 10
    };

    let mut sender = FBSSender::new(parameters.clone());
    assert_eq!(sender.parameters.id, 10);
    assert_eq!(sender.parameters.k, 40);


    let random_strings = match sender.random_strings.clone() {
        Some(random_strings) => random_strings,
        None => {
            assert_eq!(true, false);
            return;
        }
    };


    println!("alpha: {}\nbeta: {}\n\n", random_strings.alpha, random_strings.beta);

    let blinded = sender.blind("hello".to_string());
    let result = match blinded.clone() {
        Some(_) => true,
        None => false
    };

    assert_eq!(result, true);

    let signer_privkey = RSAPrivateKey::from_components(n, e, d, primes);
    let sender = FBSSigner::new(parameters.clone(), signer_privkey);

    assert_eq!(sender.parameters.id, parameters.id);
    assert_eq!(sender.parameters.k, parameters.k);
}

