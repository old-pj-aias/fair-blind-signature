pub trait EJPubKey {
    fn encrypt(&self, plain: String) -> String;
}

pub trait EJPrivKey {
    fn decrypt(&self, cipher: String) -> String;
}

pub struct Judge<EJ: EJPrivKey> {
    pub privateKey: EJ
}