use aes::Aes128;
use cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use hex_literal::hex;

fn unpad_pkcs5(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let pad_len = data[data.len() - 1] as usize;
    if pad_len == 0 || pad_len > 16 {
        return None;
    }
    if data.len() < pad_len {
        return None;
    }
    for i in (data.len() - pad_len)..data.len() {
        if data[i] != pad_len as u8 {
            return None;
        }
    }
    Some(data[..data.len() - pad_len].to_vec())
}

fn cbc_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let iv = &ciphertext[..16];
    let ct = &ciphertext[16..];

    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut plaintext = Vec::new();
    let mut prev_block = *Block::<Aes128>::from_slice(iv);

    for chunk in ct.chunks(16) {
        let mut block = *Block::<Aes128>::from_slice(chunk);
        cipher.decrypt_block(&mut block);

        for i in 0..16 {
            block[i] ^= prev_block[i];
        }

        plaintext.extend_from_slice(&block);
        prev_block = *Block::<Aes128>::from_slice(chunk);
    }

    plaintext
}

fn ctr_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let iv = &ciphertext[..16];
    let ct = &ciphertext[16..];

    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut plaintext = Vec::new();
    let mut counter = u128::from_be_bytes(iv.try_into().unwrap());

    for chunk in ct.chunks(16) {
        let mut keystream_block = *Block::<Aes128>::from_slice(&counter.to_be_bytes());
        cipher.encrypt_block(&mut keystream_block);

        for (i, &b) in chunk.iter().enumerate() {
            plaintext.push(b ^ keystream_block[i]);
        }

        counter = counter.wrapping_add(1);
    }

    plaintext
}

pub fn week2_run() {
    let key1 = hex!("140b41b22a29beb4061bda66b6747e14");

    let ct1 = hex!(
        "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    );
    let pt1 = cbc_decrypt(&key1, &ct1);
    let unpadded1 = unpad_pkcs5(&pt1).unwrap();
    println!("Question 1: {}", String::from_utf8_lossy(&unpadded1));

    let ct2 = hex!(
        "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    );
    let pt2 = cbc_decrypt(&key1, &ct2);
    let unpadded2 = unpad_pkcs5(&pt2).unwrap();
    println!("Question 2: {}", String::from_utf8_lossy(&unpadded2));

    let key2 = hex!("36f18357be4dbd77f050515c73fcf9f2");

    let ct3 = hex!(
        "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    );
    let pt3 = ctr_decrypt(&key2, &ct3);
    println!("Question 3: {}", String::from_utf8_lossy(&pt3));

    let ct4 = hex!(
        "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    );
    let pt4 = ctr_decrypt(&key2, &ct4);
    println!("Question 4: {}", String::from_utf8_lossy(&pt4));
}
