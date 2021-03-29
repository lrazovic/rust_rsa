use num_bigint::BigUint;
use std::fmt;

#[derive(Debug)]
pub struct Keys {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl Keys {
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}

impl fmt::Display for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Key Length: {}\nN: {}",
            self.public_key.key_size, self.public_key.n
        )
    }
}

#[derive(Debug)]
pub struct PublicKey {
    pub e: BigUint,
    pub n: BigUint,
    pub p: Option<BigUint>,
    pub q: Option<BigUint>,
    key_size: u64,
}

impl PublicKey {
    pub fn new(
        e: BigUint,
        n: BigUint,
        p: Option<BigUint>,
        q: Option<BigUint>,
        key_size: u64,
    ) -> Self {
        Self {
            e,
            n,
            p,
            q,
            key_size,
        }
    }

    pub fn encrypt(&self, m: BigUint) -> BigUint {
        m.modpow(&self.e, &self.n)
    }
}
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "e = {}\n", self.e)?;
        write!(f, "n = {}\n", self.n)?;
        write!(f, "key_size={}\n", self.key_size)
    }
}

#[derive(Debug)]
pub struct PrivateKey {
    pub d: BigUint,
    pub n: BigUint,
}

impl PrivateKey {
    pub fn new(d: BigUint, n: BigUint) -> Self {
        Self { d, n }
    }

    pub fn decrypt(&self, m: BigUint) -> BigUint {
        m.modpow(&self.d, &self.n)
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "d = {}\n", self.d)?;
        write!(f, "n = {}\n", self.n.to_string())
    }
}
