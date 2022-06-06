use aes::cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit,
};
use cipher::Iv;

use crate::Key;

pub(crate) type EncAlg = cbc::Encryptor<aes::Aes128>;
pub(crate) type DecAlg = cbc::Decryptor<aes::Aes128>;
pub(crate) type MacAlg = hmac::Hmac<sha2::Sha256>;

pub(crate) fn encrypt(data: impl AsRef<[u8]>, key: &Key, iv: impl AsRef<[u8]>) -> Vec<u8> {
    let mut blob = vec![0; data.as_ref().len() + EncAlg::block_size()];

    // Unwrapping since adding `CIPHER_BLOCK_SIZE` to array is enough space for
    // PKCS7
    let encrypted_len = EncAlg::new(key.as_ref().into(), iv.as_ref().into())
        .encrypt_padded_b2b_mut::<Pkcs7>(data.as_ref(), &mut blob)
        .unwrap()
        .len();

    blob.truncate(encrypted_len);

    blob
}

pub(crate) fn decrypt(
    data: impl AsRef<[u8]>,
    key: &Key,
    iv: impl AsRef<[u8]>,
) -> zeroize::Zeroizing<Vec<u8>> {
    let mut data = data.as_ref().to_vec();

    DecAlg::new(key.as_ref().into(), iv.as_ref().into())
        .decrypt_padded_mut::<Pkcs7>(&mut data)
        .unwrap()
        .to_vec()
        .into()
}

pub(crate) fn generate_iv() -> Iv<EncAlg> {
    EncAlg::generate_iv(cipher::rand_core::OsRng)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encrypt() {
        let data = b"some data";
        let expected_encrypted = &[
            241, 233, 175, 173, 142, 44, 63, 240, 77, 154, 211, 233, 217, 170, 49, 142,
        ];
        let aes_key = Key(vec![
            132, 3, 113, 222, 81, 209, 49, 43, 81, 232, 243, 46, 1, 103, 184, 42,
        ]);
        let aes_iv = &[
            78, 82, 67, 158, 214, 102, 48, 109, 84, 107, 94, 54, 225, 29, 186, 246,
        ];

        let encrypted = encrypt(data, &aes_key, aes_iv);
        assert_eq!(encrypted, expected_encrypted);

        let decrypted = decrypt(&encrypted, &aes_key, aes_iv);
        assert_eq!(decrypted.to_vec(), data);
    }
}
