use aes::cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit,
};

use crate::{error::Result, Key};

type EncAlg = cbc::Encryptor<aes::Aes128>;
type DecAlg = cbc::Decryptor<aes::Aes128>;

pub(crate) fn encrypt(data: &[u8], key: &Key, iv: &[u8]) -> Result<Vec<u8>> {
    let mut blob = vec![0; data.len() + EncAlg::block_size()];

    let encrypted_len = EncAlg::new(key.as_ref().into(), iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(data, &mut blob)
        .unwrap()
        .len();

    blob.truncate(encrypted_len);

    Ok(blob)
}

pub(crate) fn decrypt(data: &[u8], key: &Key, iv: &[u8]) -> Result<Vec<u8>> {
    let mut data = zeroize::Zeroizing::new(data.to_vec());

    let decrypted = DecAlg::new(key.as_ref().into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(data.as_mut())
        .unwrap()
        .to_vec();

    Ok(decrypted)
}

pub(crate) fn generate_iv() -> Vec<u8> {
    EncAlg::generate_iv(cipher::rand_core::OsRng).to_vec()
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

        let encrypted = encrypt(data, &aes_key, aes_iv).unwrap();
        assert_eq!(encrypted, expected_encrypted);

        let decrypted = decrypt(&encrypted, &aes_key, aes_iv).unwrap();
        assert_eq!(decrypted, data);
    }
}
