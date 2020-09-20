pub trait EJPubKey {
    fn encrypt(&self, plain: &str) -> String;
}

pub trait EJPrivKey {
    fn decrypt(&self, cipher: &str) -> String;
}

pub struct Judge<EJ: EJPrivKey> {
    pub private_key: EJ,
}
