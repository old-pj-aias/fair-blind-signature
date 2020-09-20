#[derive(PartialEq, Debug)]
pub enum VerifyError {
    NotPassed,
}

#[derive(PartialEq, Debug)]
pub enum CheckError {
    NoSubset,
    NoBlindedDigest,
    NotPassed,
}

#[derive(PartialEq, Debug)]
pub enum SignError {
    NoSubset,
    NoBlindedDigest,
}
