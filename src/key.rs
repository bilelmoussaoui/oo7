use std::ops::{Mul, Rem, Shr};

use hkdf::Hkdf;
use num::{bigint::BigUint, FromPrimitive, Integer, One, Zero};
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, Rng};
use sha2::Sha256;
use zbus::zvariant::{self, Type};
use zeroize::{Zeroize, ZeroizeOnDrop};

// for key exchange
static DH_GENERATOR: Lazy<BigUint> = Lazy::new(|| BigUint::from_u64(0x2).unwrap());
static DH_PRIME: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
        0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67,
        0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E,
        0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5,
        0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF,
        0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE,
        0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ])
});

/// A key.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Key(pub(crate) Vec<u8>);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsMut<[u8]> for Key {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Key {
    pub(crate) fn generate_private_key() -> Self {
        let mut rng = OsRng {};
        let mut private_key = Key(vec![0_u8; 128]);
        rng.fill(private_key.as_mut());

        private_key
    }

    // TODO zeroize
    pub(crate) fn generate_public_key(private_key: &Self) -> Self {
        let private_key_uint = BigUint::from_bytes_be(private_key.as_ref());
        let public_key_uint = powm(&DH_GENERATOR, &private_key_uint, &DH_PRIME);

        Key(public_key_uint.to_bytes_be())
    }

    // TODO zeroize
    pub(crate) fn generate_aes_key(private_key: &Self, server_public_key: &Self) -> Self {
        let server_public_key_uint = BigUint::from_bytes_be(server_public_key.as_ref());
        let private_key_uint = BigUint::from_bytes_be(private_key.as_ref());
        let common_secret = powm(&server_public_key_uint, &private_key_uint, &DH_PRIME);

        let mut common_secret_bytes = common_secret.to_bytes_be();
        let mut common_secret_padded = vec![0; 128 - common_secret_bytes.len()];
        // inefficient, but ok for now
        common_secret_padded.append(&mut common_secret_bytes);

        // hkdf
        // input_keying_material
        let ikm = common_secret_padded;
        let salt = None;
        let info = [];

        // output keying material
        let mut okm = Key(vec![0; 16]);

        let (_, hk) = Hkdf::<Sha256>::extract(salt, &ikm);
        hk.expand(&info, okm.as_mut())
            .expect("hkdf expand should never fail");

        okm
    }
}

impl From<&Key> for zvariant::Value<'_> {
    fn from(key: &Key) -> Self {
        let mut array = zvariant::Array::new(u8::signature());
        for byte in key.as_ref() {
            array
                .append(zvariant::Value::U8(*byte))
                .expect("Element of valid type");
        }
        array.into()
    }
}

impl From<zvariant::OwnedValue> for Key {
    fn from(value: zvariant::OwnedValue) -> Self {
        let mut key = zeroize::Zeroizing::new(vec![]);
        for value in value.downcast_ref::<zvariant::Array>().unwrap().get() {
            key.push(*value.downcast_ref::<u8>().unwrap());
        }
        Key(key.to_vec())
    }
}

/// from https://github.com/plietar/librespot/blob/master/core/src/util/mod.rs#L53
fn powm(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let mut base = base.clone();
    let mut exp = exp.clone();
    let mut result: BigUint = One::one();

    while !exp.is_zero() {
        if exp.is_odd() {
            result = result.mul(&base).rem(modulus);
        }
        exp = exp.shr(1);
        base = (&base).mul(&base).rem(modulus);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_public_pair() {
        let private_key = Key(vec![
            41, 20, 63, 236, 246, 132, 109, 70, 172, 121, 45, 66, 129, 21, 247, 91, 96, 217, 56,
            201, 205, 56, 17, 178, 202, 81, 71, 104, 233, 89, 87, 32, 88, 146, 107, 224, 56, 103,
            111, 74, 143, 80, 170, 40, 5, 52, 48, 90, 75, 71, 193, 224, 222, 57, 91, 81, 66, 1, 6,
            88, 137, 66, 102, 207, 55, 95, 67, 92, 140, 227, 242, 153, 185, 195, 89, 236, 146, 242,
            88, 215, 1, 7, 135, 254, 85, 165, 236, 110, 22, 79, 107, 254, 149, 164, 243, 94, 129,
            198, 45, 208, 132, 166, 0, 153, 243, 160, 255, 188, 59, 216, 99, 221, 85, 162, 116,
            210, 160, 117, 201, 39, 179, 123, 107, 8, 242, 139, 207, 250,
        ]);
        let server_public_key = Key(vec![
            50, 233, 76, 88, 47, 206, 235, 107, 9, 232, 98, 14, 188, 214, 209, 77, 35, 66, 109,
            119, 24, 191, 120, 90, 242, 198, 240, 115, 200, 66, 51, 180, 8, 164, 89, 9, 229, 31,
            160, 31, 156, 101, 169, 60, 63, 247, 37, 255, 75, 198, 62, 235, 50, 29, 221, 245, 29,
            248, 140, 209, 62, 215, 2, 137, 82, 77, 248, 242, 56, 176, 118, 183, 124, 74, 26, 133,
            188, 47, 31, 141, 232, 194, 92, 18, 69, 3, 56, 153, 42, 9, 143, 81, 197, 159, 200, 197,
            221, 74, 186, 157, 158, 36, 74, 125, 11, 234, 33, 2, 5, 36, 206, 248, 155, 157, 145,
            159, 238, 19, 185, 194, 134, 3, 195, 198, 60, 100, 159, 31,
        ]);

        let expected_public_key = &[
            9, 192, 210, 81, 212, 191, 74, 119, 22, 172, 81, 142, 124, 89, 17, 71, 118, 190, 81,
            71, 49, 149, 200, 204, 14, 47, 111, 165, 119, 103, 216, 102, 111, 93, 242, 64, 73, 224,
            165, 11, 127, 219, 197, 188, 168, 222, 254, 10, 104, 81, 8, 206, 237, 119, 225, 100,
            78, 196, 89, 163, 63, 169, 77, 236, 80, 241, 189, 49, 27, 40, 243, 229, 66, 53, 80, 86,
            44, 213, 87, 186, 68, 55, 216, 56, 236, 51, 229, 44, 174, 18, 87, 141, 85, 71, 185,
            203, 208, 144, 190, 117, 141, 255, 153, 106, 123, 28, 152, 200, 237, 189, 176, 20, 80,
            211, 33, 158, 232, 194, 145, 45, 194, 35, 108, 106, 214, 221, 159, 137,
        ];
        let expected_aes_key = &[
            132, 3, 113, 222, 81, 209, 49, 43, 81, 232, 243, 46, 1, 103, 184, 42,
        ];

        let public_key = Key::generate_public_key(&private_key);
        let aes_key = Key::generate_aes_key(&private_key, &server_public_key);

        assert_eq!(public_key.as_ref(), expected_public_key);
        assert_eq!(aes_key.as_ref(), expected_aes_key);
    }
}
