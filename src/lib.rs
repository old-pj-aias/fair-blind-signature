extern crate rand;
extern crate rsa;

extern crate num_bigint_dig as num_bigint;
extern crate num_traits;

use serde::{Deserialize, Serialize};

use rsa::{BigUint, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use std::vec::Vec;

use sha2::{Digest, Sha256};

use rand::distributions::{Alphanumeric, Standard};
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

use num_bigint_dig::traits::ModInverse;

const DEFALT_SIZE: usize = 256;

pub trait EJPubKey {
    fn encrypt(&self, plain: String) -> String;
}

pub trait EJPrivKey {
    fn decrypt(&self, cipher: String) -> String;
}

pub struct Judge<EJ: EJPrivKey> {
    pub private_key: EJ,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RandomStrings {
    pub alpha: String,
    pub beta: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct BlindedDigest {
    pub m: Vec<BigUint>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Unblinder {
    pub r: Vec<BigUint>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct EncryptedMessage {
    pub u: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct EncryptedID {
    pub v: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BlindSignature {
    pub b: BigUint,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    pub s: BigUint,
    pub alpha: String,
    pub encrypted_id: EncryptedID,
    pub subset: Subset,
}

#[derive(Clone)]
pub struct FBSParameters<EJ: EJPubKey> {
    pub judge_pubkey: EJ,
    pub signer_pubkey: RSAPublicKey,
    pub k: u32,
    pub id: u32,
}

#[derive(Clone)]
pub struct FBSSender<EJ: EJPubKey> {
    pub parameters: FBSParameters<EJ>,
    pub random_strings: Option<RandomStrings>,
    pub blinded_digest: Option<BlindedDigest>,
    pub unblinder: Option<Unblinder>,
    pub encrypted_message: Option<EncryptedMessage>,
    pub encrypted_id: Option<EncryptedID>,
    pub subset: Option<Subset>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Subset {
    pub subset: Vec<u32>,
    pub complement: Vec<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CheckParameter {
    pub part_of_encrypted_message: EncryptedMessage,
    pub part_of_unblinder: Unblinder,
    pub part_of_beta: Vec<u8>,
}

pub struct FBSSigner<EJ: EJPubKey> {
    pub parameters: FBSParameters<EJ>,
    pub blinded_digest: Option<BlindedDigest>,
    pub subset: Option<Subset>,
    pub check: Option<CheckParameter>,
    pub privkey: RSAPrivateKey,
}

#[derive(Clone)]
pub struct FBSVerifyer<EJ: EJPubKey> {
    pub parameters: FBSParameters<EJ>,
}

fn generate_random_ubigint(size: usize) -> BigUint {
    let size = size / 32;
    let random_bytes: Vec<u32> = thread_rng()
        .sample_iter(Standard)
        .take(size)
        .collect();
    return BigUint::new(random_bytes);
}

fn generate_random_string(len: u32) -> String {
    thread_rng().sample_iter(&Alphanumeric).take(len as usize).collect()
}

impl<EJ: EJPubKey> FBSSigner<EJ> {
    pub fn new(parameters: FBSParameters<EJ>, privkey: RSAPrivateKey) -> FBSSigner<EJ> {
        FBSSigner {
            parameters: parameters,
            blinded_digest: None,
            check: None,
            subset: None,
            privkey: privkey,
        }
    }

    pub fn setup_subset(&mut self) -> Subset {
        let len = 2 * self.parameters.k + 1;
        let all: Vec<u32> = (1..len).collect();

        let mut complement = Vec::new();

        let mut rng = thread_rng();
        let mut subset: Vec<u32> = all
            .choose_multiple(&mut rng, self.parameters.k as usize)
            .cloned()
            .collect();
        subset.sort();

        for i in all {
            if let Err(_) = subset.binary_search(&i) {
                complement.push(i);
            }
        }

        let subset = Subset {
            complement: complement,
            subset: subset,
        };

        self.subset = Some(subset.clone());

        // TODO: we can return reference (like `&self.subset`)
        subset
    }

    pub fn set_blinded_digest(&mut self, blinded_digest: BlindedDigest) {
        self.blinded_digest = Some(blinded_digest);
    }

    pub fn check(&self, check_parameter: CheckParameter) -> bool {
        let subset = match &self.subset {
            Some(subset) => &subset.subset,
            None => return false,
        };

        let len = subset.len() - 1;

        for subset_index in 0..len {
            let all_index = subset[subset_index] as usize;

            let v_i = format!(
                "{}:{}",
                self.parameters.id, check_parameter.part_of_beta[subset_index]
            );
            let v_i = self.parameters.judge_pubkey.encrypt(v_i);

            let r_e_i = check_parameter.part_of_unblinder.r[subset_index].modpow(
                self.parameters.signer_pubkey.e(),
                self.parameters.signer_pubkey.n(),
            );

            let h_i = format!(
                "{}:{}",
                check_parameter.part_of_encrypted_message.u[subset_index], v_i
            );

            let mut hasher = Sha256::new();
            hasher.update(h_i);
            let h_i = hasher.finalize();
            let h_i = BigUint::from_bytes_le(&h_i);

            let m_i = r_e_i * h_i % self.parameters.signer_pubkey.n();

            let blinded_digest = match &self.blinded_digest {
                Some(blinded_digest) => blinded_digest,
                None => return false,
            };

            if m_i != blinded_digest.m[all_index] {
                return false;
            }
        }

        true
    }

    pub fn sign(&self) -> Option<BlindSignature> {
        let one = BigUint::from(1u32);
        let mut blind_signature = BlindSignature { b: one };

        for complement_index in 0..self.subset.clone()?.complement.len() - 1 {
            let complement_index = complement_index as usize;
            let all_index = self.subset.clone()?.subset[complement_index] as usize;

            let digest = self.blinded_digest.clone()?.m[all_index].clone()
                % self.parameters.signer_pubkey.n();
            blind_signature.b *= digest;
            blind_signature.b %= self.parameters.signer_pubkey.n();
        }

        blind_signature.b = blind_signature
            .b
            .modpow(self.privkey.d(), self.parameters.signer_pubkey.n());

        return Some(blind_signature);
    }
}

impl<EJ: EJPubKey> FBSSender<EJ> {
    pub fn new(parameters: FBSParameters<EJ>) -> FBSSender<EJ> {
        let len: u32 = 2 * parameters.k * 8;

        let random_strings = Some(RandomStrings {
            alpha: generate_random_string(len),
            beta: generate_random_string(len),
        });

        FBSSender {
            parameters: parameters,
            random_strings: random_strings,
            blinded_digest: None,
            unblinder: None,
            encrypted_message: None,
            encrypted_id: None,
            subset: None,
        }
    }

    pub fn blind(
        &mut self,
        message: String,
    ) -> Option<(BlindedDigest, Unblinder, EncryptedMessage, EncryptedID)> {
        let mut r = Vec::new();
        let mut u = Vec::new();
        let mut v = Vec::new();
        let mut m = Vec::new();

        let len = 2 * self.parameters.k as usize;
        let alpha = self.random_strings.as_ref()?.alpha.as_bytes();
        let beta = self.random_strings.as_ref()?.beta.as_bytes();

        for i in 0..len {
            let r_i = generate_random_ubigint(DEFALT_SIZE);

            let u_i = format!("{}:{}", message, alpha[i]);
            let u_i = self.parameters.judge_pubkey.encrypt(u_i);

            let v_i = format!("{}:{}", self.parameters.id, beta[i]);
            let v_i = self.parameters.judge_pubkey.encrypt(v_i);

            let r_e_i = r_i.modpow(
                self.parameters.signer_pubkey.e(),
                self.parameters.signer_pubkey.n(),
            );

            let h_i = format!("{}:{}", u_i, v_i);

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

        let blinded_digest = BlindedDigest { m };
        let unblinder = Unblinder { r };
        let encrypted_message = EncryptedMessage { u };
        let encrypted_id = EncryptedID { v };

        self.blinded_digest = Some(blinded_digest.clone());
        self.unblinder = Some(unblinder.clone());
        self.encrypted_message = Some(encrypted_message.clone());
        self.encrypted_id = Some(encrypted_id.clone());

        // TODO: we can return reference
        Some((blinded_digest, unblinder, encrypted_message, encrypted_id))
    }

    pub fn set_subset(&mut self, subset: Subset) {
        self.subset = Some(subset);
    }

    pub fn generate_check_parameter(&self) -> Option<CheckParameter> {
        let mut u = Vec::new();
        let mut r = Vec::new();
        let mut beta = Vec::new();

        let all_u = &self.encrypted_message.as_ref()?.u;
        let all_r = &self.unblinder.as_ref()?.r;

        let beta_bytes = self.random_strings.as_ref()?.beta.as_bytes();

        let len = self.subset.as_ref()?.complement.len() - 1;

        for complement_index in 0..len {
            let complement_index = complement_index;
            let all_index = self.subset.clone()?.subset[complement_index] as usize;

            let u_i = all_u[all_index].clone();
            let r_i = all_r[all_index].clone();
            let beta_i = beta_bytes[all_index].clone();

            u.push(u_i);
            r.push(r_i);
            beta.push(beta_i);
        }

        Some(CheckParameter {
            part_of_encrypted_message: EncryptedMessage { u },
            part_of_unblinder: Unblinder { r },
            part_of_beta: beta,
        })
    }

    pub fn unblind(&self, blind_signature: BlindSignature) -> Option<Signature> {
        let b = blind_signature.b.clone();
        let mut r = BigUint::from(1u32);

        let len = self.subset.clone()?.complement.len() - 1;
        for complement_index in 0..len {
            let all_index = self.subset.clone()?.subset[complement_index] as usize;

            r *= &self.unblinder.as_ref()?.r[all_index];
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
            alpha: self.random_strings.as_ref()?.alpha.clone(),
            encrypted_id: self.encrypted_id.clone()?,
            subset: self.subset.clone()?,
        })
    }
}

impl<EJ: EJPubKey> FBSVerifyer<EJ> {
    pub fn new(parameters: FBSParameters<EJ>) -> FBSVerifyer<EJ> {
        FBSVerifyer {
            parameters,
        }
    }

    pub fn verify(&self, signature: Signature, message: String) -> bool {
        let s_e = signature.s.modpow(
            self.parameters.signer_pubkey.e(),
            self.parameters.signer_pubkey.n(),
        );

        let alpha = signature.alpha.as_bytes();

        let mut s = BigUint::from(1u32);

        let len = signature.subset.complement.len() - 1;
        for complement_index in 0..len {
            let all_index = signature.subset.subset[complement_index] as usize;

            let u_i = format!("{}:{}", message, alpha[all_index]);
            let u_i = self.parameters.judge_pubkey.encrypt(u_i);

            let h_i = format!("{}:{}", u_i, signature.encrypted_id.v[all_index]);

            let mut hasher = Sha256::new();
            hasher.update(h_i);
            let h_i = hasher.finalize();
            let h_i = BigUint::from_bytes_le(&h_i);

            s *= h_i % self.parameters.signer_pubkey.n();
            s %= self.parameters.signer_pubkey.n();
        }

        return s == s_e;
    }
}

impl<EJ: EJPrivKey> Judge<EJ> {
    pub fn new(privkey: EJ) -> Self {
        return Self {
            private_key: privkey,
        };
    }

    pub fn open(&self, encrypted_id: EncryptedID) -> String {
        self.private_key.decrypt(encrypted_id.v[0].clone())
            .split(":")
            .nth(0)
            .unwrap()
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_generate_random_ubigint() {
        for i in 1..20 {
            let size = i * 64;
            let random = generate_random_ubigint(size);
            println!("{:x}\n\n\n", random);
        }
    }

    #[test]
    fn should_generate_random_string() {
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
    fn all() {
        let n = BigUint::from(882323119 as u32);
        let e = BigUint::from(7 as u32);
        let d = BigUint::from(504150583 as u32);
        let primes = [BigUint::from(27409 as u32), BigUint::from(32191 as u32)].to_vec();

        let signer_pubkey = RSAPublicKey::new(n.clone(), e.clone()).unwrap();
        let judge_pubkey = TestCipherPubkey {};
        let judge_privkey = TestCipherPrivkey {};

        let parameters = FBSParameters {
            signer_pubkey: signer_pubkey,
            judge_pubkey: judge_pubkey,
            k: 40,
            id: 10,
        };

        let mut sender = FBSSender::new(parameters.clone());
        assert_eq!(sender.parameters.id, 10);
        assert_eq!(sender.parameters.k, 40);

        let random_strings = sender.random_strings.as_ref().unwrap().clone();

        println!(
            "alpha: {}\nbeta: {}\n\n",
            random_strings.alpha, random_strings.beta
        );

        let blinded = sender.blind("hello".to_string());

        assert_ne!(blinded, None);

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

        let result = signer.check(check_parameter);
        assert_eq!(result, true);

        let sign = signer.sign().unwrap();
        let signature = sender.clone().unblind(sign).unwrap();

        println!("s: {}", signature.s);

        let verifyer = FBSVerifyer::new(parameters);
        let result = verifyer.verify(signature.clone(), "hello".to_string());

        assert_eq!(result, true);

        let judge = Judge::new(judge_privkey);
        let result = judge.open(signature.encrypted_id);

        assert_eq!(result, "10");
    }

    #[test]
    fn speed() {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let bits = 2048;
        let signer_privkey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let signer_pubkey = RSAPublicKey::from(&signer_privkey);

        let judge_pubkey = TestCipherPubkey {};
        let judge_privkey = TestCipherPrivkey {};

        let parameters = FBSParameters {
            signer_pubkey: signer_pubkey,
            judge_pubkey: judge_pubkey,
            k: 40,
            id: 10,
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

        println!(
            "alpha: {}\nbeta: {}\n\n",
            random_strings.alpha, random_strings.beta
        );

        let blinded = sender.blind("hello".to_string());
        let result = match blinded.clone() {
            Some(_) => true,
            None => false,
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

        let result = signer.check(check_parameter);
        assert_eq!(result, true);

        let sign = signer.sign().unwrap();
        let signature = sender.clone().unblind(sign).unwrap();

        println!("s: {}", signature.s);

        let verifyer = FBSVerifyer::new(parameters);
        let result = verifyer.verify(signature.clone(), "hello".to_string());

        assert_eq!(result, true);

        let judge = Judge::new(judge_privkey);
        let result = judge.open(signature.encrypted_id);

        assert_eq!(result, "10");
    }
}
