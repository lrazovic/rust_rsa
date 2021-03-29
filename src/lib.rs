mod keys;

use glass_pumpkin::prime;
use keys::{Keys, PrivateKey, PublicKey};
use num::bigint::{BigInt, BigUint, ToBigInt};
use num::Integer;
use num::{One, Zero};
use num_bigint::RandBigInt;
use std::mem::swap;

// From https://rosettacode.org/wiki/Modular_inverse#Rust
fn mod_inverse(a: &BigUint, module: &BigUint) -> Option<BigUint> {
    let (zero, one): (BigInt, BigInt) = (Zero::zero(), One::one());
    let (mut x, mut y): (BigInt, BigInt) = (Zero::zero(), One::one());
    let (mut m, mut n) = (module.to_bigint().unwrap(), a.to_bigint().unwrap());
    while !n.is_zero() {
        let quotient = &m / &n;
        let mut temp: BigInt = &x - &quotient * &y;
        swap(&mut x, &mut y);
        swap(&mut y, &mut temp);
        temp = &m - &quotient * &n;
        swap(&mut m, &mut n);
        swap(&mut n, &mut temp);
    }
    if m > one {
        return None;
    };
    if x < zero {
        x = &x + &module.to_bigint().unwrap()
    };
    x.to_biguint()
}

fn generate_primes(bits: usize) -> (BigUint, BigUint, BigUint) {
    let p: BigUint = prime::new(bits).unwrap();
    let q: BigUint = prime::new(bits).unwrap();
    let n = &p * &q;
    (p, q, n)
}

pub fn generate_keys(exp: Option<BigUint>) -> Option<Keys> {
    // Generate two primes (p,q,_) of 512 bits each, and (_,_,n) of 1024 bits
    let (p, q, n) = generate_primes(512);
    let one: BigUint = One::one();
    let lambda_n: BigUint = (&p - &one).lcm(&(&q - &one));
    let mut e = match exp {
        Some(e) => e,
        None => Zero::zero(),
    };
    loop {
        // e is released as part of the public key.
        if e.is_zero() {
            e = rand::thread_rng().gen_biguint_range(&one, &(&lambda_n - &one));
        }
        if e.gcd(&lambda_n).is_one() {
            // d is kept secret as the private key exponent.
            let public = PublicKey::new(e.clone(), n.clone(), Some(p), Some(q), n.bits());
            let d = mod_inverse(&e, &lambda_n);
            match d {
                Some(d) => {
                    let private = PrivateKey::new(d, n);
                    return Some(Keys::new(public, private));
                }
                None => return None,
            };
        } else {
            e = rand::thread_rng().gen_biguint_range(&one, &(&lambda_n - &one));
        }
    }
}
#[test]
fn check_encryption_and_decryption() {
    let keys: Keys;
    match generate_keys(None) {
        Some(succ) => keys = succ,
        None => {
            println!("Error in key generation.");
            return;
        }
    }
    let testo = String::from("S3cr3t_m3ss4g3");
    let mess = BigUint::from_bytes_be(testo.as_bytes());
    let encrypted = keys.public_key.encrypt(mess);
    let decrypted = keys.private_key.decrypt(encrypted);
    let dec_mess = decrypted.to_bytes_be();
    assert_eq!(testo, String::from_utf8(dec_mess).unwrap())
}

#[test]
fn check_inv_mod() {
    use num::bigint::ToBigUint;

    let a: BigUint = BigUint::from(42u32);
    let n: BigUint = BigUint::from(2017u32);
    let result = mod_inverse(&a, &n);
    assert_eq!(result.unwrap(), 1969.to_biguint().unwrap())
}

#[test]
fn check_encryption_and_decryption_given_exp() {
    use num::bigint::ToBigUint;

    let keys: Keys;
    match generate_keys(Some(65537.to_biguint().unwrap())) {
        Some(succ) => keys = succ,
        None => {
            println!("Error in key generation.");
            return;
        }
    }
    let testo = String::from("S3cr3t_m3ss4g3");
    let mess = BigUint::from_bytes_be(testo.as_bytes());
    let encrypted = keys.public_key.encrypt(mess);
    let decrypted = keys.private_key.decrypt(encrypted);
    let dec_mess = decrypted.to_bytes_be();
    assert_eq!(testo, String::from_utf8(dec_mess).unwrap())
}

#[test]
fn wikipedia_test() {
    use num::bigint::ToBigUint;

    let e = 17.to_biguint().unwrap();
    let n = 3233.to_biguint().unwrap();
    let d = 413.to_biguint().unwrap();
    let public = PublicKey::new(e, n.clone(), None, None, n.bits());
    let private = PrivateKey::new(d, n);
    let mess = 65.to_biguint().unwrap();
    let encrypted = public.encrypt(mess);
    let decrypted = private.decrypt(encrypted);
    assert_eq!(65.to_biguint().unwrap(), decrypted)
}

#[test]
fn check_correcttness_versus_real_world() {
    use openssl::bn::BigNum;
    use openssl::rsa::{Padding, RsaPrivateKeyBuilder};

    let keys: Keys;
    match generate_keys(None) {
        Some(succ) => keys = succ,
        None => {
            println!("Error in key generation.");
            return;
        }
    }
    let n_rsa = BigNum::from_dec_str(&keys.public_key.n.clone().to_string()).unwrap();
    let e_rsa = BigNum::from_dec_str(&keys.public_key.e.clone().to_string()).unwrap();
    let d_rsa = BigNum::from_dec_str(&keys.private_key.d.clone().to_string()).unwrap();
    let p_rsa = BigNum::from_dec_str(&keys.public_key.p.clone().unwrap().to_string()).unwrap();
    let q_rsa = BigNum::from_dec_str(&keys.public_key.q.clone().unwrap().to_string()).unwrap();
    let rsa_wrt = RsaPrivateKeyBuilder::new(n_rsa, e_rsa, d_rsa)
        .unwrap()
        .set_factors(p_rsa, q_rsa)
        .unwrap()
        .build();
    let string = String::from("S3cr3t_m3ss4g3");
    let data = string.as_bytes();
    let mut buf = vec![0; rsa_wrt.size() as usize];
    let _ = rsa_wrt
        .public_encrypt(data, &mut buf, Padding::PKCS1_OAEP)
        .unwrap();
    let mut dec_buf = vec![0; rsa_wrt.size() as usize];
    let _ = rsa_wrt.private_decrypt(&buf, &mut dec_buf, Padding::PKCS1_OAEP);
    let testo = String::from("S3cr3t_m3ss4g3");
    let mess = BigUint::from_bytes_be(testo.as_bytes());
    let encrypted = keys.public_key.encrypt(mess);
    let decrypted = keys.private_key.decrypt(encrypted);
    let dec_mess = decrypted.to_bytes_be();
    assert_eq!(
        String::from_utf8(dec_buf.to_vec())
            .unwrap()
            .trim_matches(char::from(0)),
        String::from_utf8(dec_mess).unwrap()
    )
}

#[test]
fn check_time_rsa_versus_real_world() {
    use openssl::rsa::{Padding, Rsa};
    use std::time::Instant;

    let now = Instant::now();
    let keys: Keys;
    match generate_keys(None) {
        Some(succ) => keys = succ,
        None => {
            println!("Error in key generation.");
            return;
        }
    }
    println!("My Key Generation {}us", now.elapsed().as_micros());
    let now = Instant::now();
    let rsa_wrt = Rsa::generate(1024).unwrap();
    println!("OpenSSL Key Generation {}us", now.elapsed().as_micros());
    let now = Instant::now();
    let string = String::from("S3cr3t_m3ss4g3");
    let data = string.as_bytes();
    let mut buf = vec![0; rsa_wrt.size() as usize];
    let _ = rsa_wrt
        .public_encrypt(data, &mut buf, Padding::PKCS1_OAEP)
        .unwrap();
    let mut dec_buf = vec![0; rsa_wrt.size() as usize];
    let _ = rsa_wrt.private_decrypt(&buf, &mut dec_buf, Padding::PKCS1_OAEP);
    println!("OpenSSL RSA enc + dec {}us", now.elapsed().as_micros());
    let now = Instant::now();
    let testo = String::from("S3cr3t_m3ss4g3");
    let mess = BigUint::from_bytes_be(testo.as_bytes());
    let encrypted = keys.public_key.encrypt(mess);
    let decrypted = keys.private_key.decrypt(encrypted);
    let dec_mess = decrypted.to_bytes_be();
    println!("My RSA enc + dec {}us", now.elapsed().as_micros());
    assert_eq!(
        String::from_utf8(dec_buf.to_vec())
            .unwrap()
            .trim_matches(char::from(0)),
        String::from_utf8(dec_mess).unwrap()
    )
}

#[test]
fn check_time_rsa_given_e_versus_real_world() {
    use num::bigint::ToBigUint;
    use openssl::rsa::{Padding, Rsa};
    use std::time::Instant;

    let now = Instant::now();
    let keys: Keys;
    let e = 65537.to_biguint().unwrap();
    match generate_keys(Some(e)) {
        Some(succ) => keys = succ,
        None => {
            println!("Error in key generation.");
            return;
        }
    }
    println!("My Key Generation {}us", now.elapsed().as_micros());
    let now = Instant::now();
    let rsa_wrt = Rsa::generate(1024).unwrap();
    println!("OpenSSL Key Generation {}us", now.elapsed().as_micros());
    let now = Instant::now();
    let string = String::from("S3cr3t_m3ss4g3");
    let data = string.as_bytes();
    let mut buf = vec![0; rsa_wrt.size() as usize];
    let _ = rsa_wrt
        .public_encrypt(data, &mut buf, Padding::PKCS1_OAEP)
        .unwrap();
    let mut dec_buf = vec![0; rsa_wrt.size() as usize];
    let _ = rsa_wrt.private_decrypt(&buf, &mut dec_buf, Padding::PKCS1_OAEP);
    println!("OpenSSL RSA enc + dec {}us", now.elapsed().as_micros());
    let now = Instant::now();
    let testo = String::from("S3cr3t_m3ss4g3");
    let mess = BigUint::from_bytes_be(testo.as_bytes());
    let encrypted = keys.public_key.encrypt(mess);
    let decrypted = keys.private_key.decrypt(encrypted);
    let dec_mess = decrypted.to_bytes_be();
    println!("My RSA enc + dec {}us", now.elapsed().as_micros());
    assert_eq!(
        String::from_utf8(dec_buf.to_vec())
            .unwrap()
            .trim_matches(char::from(0)),
        String::from_utf8(dec_mess).unwrap()
    )
}

#[test]
fn check_time_aes_versus_real_world() {
    use openssl::symm::{decrypt, encrypt, Cipher};
    use std::time::Instant;

    let now = Instant::now();
    let keys: Keys;
    match generate_keys(None) {
        Some(succ) => keys = succ,
        None => {
            println!("Error in key generation.");
            return;
        }
    }
    println!("RSA key-gen {}us", now.elapsed().as_micros());
    let now = Instant::now();
    let testo = String::from("S3cr3t_m3ss4g3");
    let mess = BigUint::from_bytes_be(testo.as_bytes());
    let encrypted = keys.public_key.encrypt(mess);
    let decrypted = keys.private_key.decrypt(encrypted);
    let _ = decrypted.to_bytes_be();
    println!("Enc + Dec RSA {}us", now.elapsed().as_micros());

    let now = Instant::now();
    let cipher = Cipher::aes_128_cbc();
    let data = b"Some Crypto Text";
    let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";
    let ciphertext = encrypt(cipher, key, Some(iv), data).unwrap();
    let _ = decrypt(cipher, key, Some(iv), &ciphertext).unwrap();
    println!("Full OpenSSL AES-128-CBC {}us", now.elapsed().as_micros());
}
