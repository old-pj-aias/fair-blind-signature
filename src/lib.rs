extern crate rsa;
extern crate rand;

extern crate num_bigint_dig as num_bigint;
extern crate num_traits;

use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};


use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PublicKeyParts};
use std::vec::Vec;

use sha2::{Sha256, Digest};

use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use rand::seq::SliceRandom;

use num_bigint_dig::traits::ModInverse;

const DEFALT_SIZE: usize = 256;


pub trait EJPubKey {
    fn encrypt(&self, plain: String) -> String;
}

pub trait EJPrivKey {
    fn decrypt(&self, cipher: String) -> String;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RandomStrings {
    pub alpha: String,
    pub beta: String
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BlindedDigest {
    pub m: Vec<BigUint>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Unblinder {
    pub r: Vec<BigUint>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub u: Vec<String>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedID {
    pub v: Vec<String>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BlindSignature {
    pub b: BigUint
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    pub s: BigUint,
    pub alpha: String,
    pub encrypted_id: EncryptedID,
    pub subset: Subset
}

#[derive(Clone)]
pub struct FBSParameters<EJ: EJPubKey> {
    pub judge_pubkey: EJ,
    pub signer_pubkey: RSAPublicKey,
    pub k: u32,
    pub id: u32
}

#[derive(Clone)]
pub struct FBSSender<EJ: EJPubKey> {
    pub parameters: FBSParameters<EJ>,
    pub random_strings: Option<RandomStrings>,
    pub blinded_digest: Option<BlindedDigest>,
    pub unblinder: Option<Unblinder>,
    pub encrypted_message: Option<EncryptedMessage>,
    pub encrypted_id:  Option<EncryptedID>,
    pub subset: Option<Subset>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Subset {
    pub subset: Vec<u32>,
    pub complement: Vec<u32>
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CheckParameter {
    pub part_of_encrypted_message: EncryptedMessage,
    pub part_of_unblinder: Unblinder,
    pub part_of_beta: Vec<u8>
}

pub struct FBSSigner<EJ: EJPubKey> {
    pub parameters: FBSParameters<EJ>,
    pub blinded_digest: Option<BlindedDigest>,
    pub subset: Option<Subset>,
    pub check: Option<CheckParameter>,
    pub privkey: RSAPrivateKey
}

#[derive(Clone)]
pub struct FBSVerifyer<EJ: EJPubKey> {
    pub parameters: FBSParameters<EJ>
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

    pub fn setup_subset(&mut self) -> Subset { 
        let mut all : Vec<u32> = (1..(2 * self.parameters.k + 1)).map(|x: u32| x).collect();

        let mut complement = Vec::new();

        let mut rng = thread_rng();
        let mut subset : Vec<u32> = all.choose_multiple(&mut rng, self.parameters.k as usize).cloned().collect();
        subset.sort();

        for i in all.clone() {
            match subset.binary_search(&i) {
                Ok(_) => {}
                Err(_) => {
                    complement.push(i);
                }
            };
        }

        let subset = Subset {
            complement: complement,
            subset: subset
        };

        self.subset = Some(subset.clone());
        
        subset
    }

    pub fn set_blinded_digest(&mut self, blinded_digest: BlindedDigest) {
        self.blinded_digest = Some(blinded_digest);
    }

    pub fn check(&self, check_parameter: CheckParameter) -> Option<bool> {
        for subset_index in 0..self.subset.clone()?.subset.len() - 1{
            let subset_index = subset_index as usize;
            let all_index = self.subset.clone()?.subset[subset_index] as usize;

            let v_i = format!("{}{}", self.parameters.id, check_parameter.part_of_beta[subset_index]);
            let v_i = self.parameters.judge_pubkey.encrypt(v_i);

            let r_e_i = check_parameter.part_of_unblinder.r[subset_index].modpow(self.parameters.signer_pubkey.e(), self.parameters.signer_pubkey.n());

            let h_i = format!("{}{}", check_parameter.part_of_encrypted_message.u[subset_index], v_i);

            let mut hasher = Sha256::new();
            hasher.update(h_i);
            let h_i = hasher.finalize();
            let h_i = BigUint::from_bytes_le(&h_i);

            let m_i = r_e_i * h_i % self.parameters.signer_pubkey.n();
            
            if m_i != self.blinded_digest.clone()?.m[all_index] {
                return Some(false);
            }
        }

        return Some(true);
    }

    pub fn sign(&self) -> Option<BlindSignature> {
        let one = BigUint::from(1 as u32);
        let mut blind_signature = BlindSignature { b: one };

        for complement_index in 0..self.subset.clone()?.complement.len() - 1{
            let complement_index = complement_index as usize;
            let all_index = self.subset.clone()?.subset[complement_index] as usize;


            let digest = self.blinded_digest.clone()?.m[all_index].clone() % self.parameters.signer_pubkey.n();
            blind_signature.b *= digest;
            blind_signature.b %= self.parameters.signer_pubkey.n();
        }

        blind_signature.b = blind_signature.b.modpow(self.privkey.d(), self.parameters.signer_pubkey.n());

        return Some(blind_signature);
    }
}

impl <EJ: EJPubKey>FBSSender<EJ> {
    pub fn new(parameters: FBSParameters<EJ>) -> FBSSender<EJ>{
        let parameters = parameters;

        let len = 2 * parameters.k * 8;

        let random_strings = Some(RandomStrings {
            alpha: generate_random_string(len as usize),
            beta:  generate_random_string(len as usize)
        });

        FBSSender { 
            parameters: parameters,
            random_strings: random_strings,
            blinded_digest: None,
            unblinder: None,
            encrypted_message: None,
            encrypted_id: None,
            subset: None
        }
    }

    pub fn blind(&mut self, message: String) -> Option<(BlindedDigest, Unblinder, EncryptedMessage, EncryptedID)> {
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
        let encrypted_message = EncryptedMessage { u: u };
        let encrypted_id = EncryptedID { v: v };

        self.blinded_digest = Some(blinded_digest.clone());
        self.unblinder = Some(unblinder.clone());
        self.encrypted_message = Some(encrypted_message.clone());
        self.encrypted_id = Some(encrypted_id.clone());

        Some((blinded_digest, unblinder, encrypted_message, encrypted_id))
    }

    pub fn set_subset(&mut self, subset: Subset) {
        self.subset = Some(subset);
    }

    pub fn generate_check_parameter(self) -> Option<CheckParameter>{
        let mut u = Vec::new();
        let mut r = Vec::new();
        let mut beta = Vec::new();

        let all_u = self.encrypted_message?.u;
        let all_r = self.unblinder?.r;

        let beta_bytes = self.random_strings.as_ref()?.beta.as_bytes();

        for complement_index in 0..self.subset.clone()?.complement.len() - 1 {
            let complement_index = complement_index as usize;
            let all_index = self.subset.clone()?.subset[complement_index] as usize;

            let u_i = all_u[all_index].clone();
            let r_i = all_r[all_index].clone();
            let beta_i = beta_bytes[all_index].clone();

            u.push(u_i);
            r.push(r_i);
            beta.push(beta_i);
        }

        Some(CheckParameter {
            part_of_encrypted_message: EncryptedMessage { u: u },
            part_of_unblinder: Unblinder { r: r },
            part_of_beta: beta
        })
    }

    pub fn unblind(self, blind_signature: BlindSignature) -> Option<Signature> {
        let b = blind_signature.b.clone();
        let mut r = BigUint::from(1 as u32);

        for complement_index in 0..self.subset.clone()?.complement.len() - 1{
            let complement_index = complement_index as usize;
            let all_index = self.subset.clone()?.subset[complement_index] as usize;
            
            let r_i = self.unblinder.clone()?.r[all_index].clone();

            r *= r_i.clone();
            r %= self.parameters.signer_pubkey.n();
        }

        let biguint_r = num_bigint::BigUint::from_bytes_le(&r.to_bytes_le());

        let biguint_n = self.parameters.signer_pubkey.n().to_bytes_le();
        let biguint_n = num_bigint::BigUint::from_bytes_le(&biguint_n);

        let r_inverse = biguint_r.mod_inverse(biguint_n)?;
        let (_, r_inverse) = &r_inverse.to_bytes_le();

        let r_inverse = BigUint::from_bytes_le(r_inverse);
        let s = (b * r_inverse) % self.parameters.signer_pubkey.n();

        Some(Signature {
            s: s,
            alpha: self.random_strings?.alpha,
            encrypted_id: self.encrypted_id?,
            subset: self.subset?
        })
    }
}

impl <EJ: EJPubKey>FBSVerifyer<EJ>{
    pub fn new(parameters: FBSParameters<EJ>) -> FBSVerifyer<EJ> {
        let parameters = parameters;

        FBSVerifyer { 
            parameters: parameters,
        }
    }

    pub fn verify(self, signature: Signature, message: String) -> Option<bool> {
        let s_e = signature.s.modpow(self.parameters.signer_pubkey.e(), self.parameters.signer_pubkey.n());

        let alpha = signature.alpha.as_bytes();

        let mut s = BigUint::from(1 as u32);

        for complement_index in 0..signature.subset.complement.len() - 1 {
            let complement_index = complement_index as usize;
            let all_index = signature.subset.subset[complement_index] as usize;
            
            let u_i = format!("{}{}", message, alpha[all_index as usize]);
            let u_i = self.parameters.judge_pubkey.encrypt(u_i);

            let h_i = format!("{}{}", u_i, signature.encrypted_id.v[all_index]);

            let mut hasher = Sha256::new();
            hasher.update(h_i);
            let h_i = hasher.finalize();
            let h_i = BigUint::from_bytes_le(&h_i);

            s *= h_i % self.parameters.signer_pubkey.n();
            s %= self.parameters.signer_pubkey.n();
        }

        return Some(s == s_e);
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

#[derive(Clone)]
struct TestCipherPrivkey {}

impl EJPubKey for TestCipherPubkey {
    fn encrypt(&self, message: String) -> String {
        return message;
    }
}

impl EJPrivKey for TestCipherPrivkey {
    fn decrypt(&self, message: String) -> String {
        return message;
    }
}



#[test]
fn test_all() {
    let n = BigUint::from(882323119 as u32);
    let e = BigUint::from(7 as u32);
    let d = BigUint::from(504150583 as u32);
    let primes = [BigUint::from(27409 as u32), BigUint::from(32191 as u32)].to_vec();
    
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
    let mut signer = FBSSigner::new(parameters.clone(), signer_privkey);

    assert_eq!(sender.parameters.id, parameters.id);
    assert_eq!(sender.parameters.k, parameters.k);

    signer.set_blinded_digest(sender.blinded_digest.clone().unwrap());

    let subset = signer.setup_subset();
    println!("subset: {:?}", subset.subset);
    println!("complement: {:?}", subset.complement);

    sender.set_subset(subset);
    let check_parameter = sender.clone().generate_check_parameter().unwrap();

    let result = signer.check(check_parameter).unwrap();
    assert_eq!(result, true);

    let sign = signer.sign().unwrap();
    let signature = sender.clone().unblind(sign).unwrap();

    println!("s: {}", signature.s);
    
    let verifyer = FBSVerifyer::new(parameters);
    let result = verifyer.verify(signature, "hello".to_string()).unwrap();

    assert_eq!(result, true);
}


#[test]
fn test_speed() {
    let mut rng = OsRng;
    let bits = 2048;
    let signer_privkey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let signer_pubkey = RSAPublicKey::from(&signer_privkey);

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

    let mut signer = FBSSigner::new(parameters.clone(), signer_privkey);

    assert_eq!(sender.parameters.id, parameters.id);
    assert_eq!(sender.parameters.k, parameters.k);

    signer.set_blinded_digest(sender.blinded_digest.clone().unwrap());

    let subset = signer.setup_subset();
    println!("subset: {:?}", subset.subset);
    println!("complement: {:?}", subset.complement);

    sender.set_subset(subset);
    let check_parameter = sender.clone().generate_check_parameter().unwrap();

    let result = signer.check(check_parameter).unwrap();
    assert_eq!(result, true);

    let sign = signer.sign().unwrap();
    let signature = sender.clone().unblind(sign).unwrap();

    println!("s: {}", signature.s);
    
    let verifyer = FBSVerifyer::new(parameters);
    let result = verifyer.verify(signature, "hello".to_string()).unwrap();

    assert_eq!(result, true);
}

