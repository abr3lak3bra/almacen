use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose, Engine};
use ring::{
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
};

use crate::constantes;

pub fn hash_pwd(pwd: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| anyhow!("Error: Failed to generate salt for password hash"))?;

    let mut pbkdf2_hash = [0u8; 32]; // 256 bits
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(10000).unwrap(),
        &salt,
        pwd.as_bytes(),
        &mut pbkdf2_hash,
    );

    let salt_b64 = general_purpose::STANDARD.encode(salt);
    let hash_b64 = general_purpose::STANDARD.encode(pbkdf2_hash);

    Ok(format!("{salt_b64}:{hash_b64}"))
}

pub fn verify_pwd(pwd: &str, hash: &str) -> Result<bool> {
    let partes: Vec<&str> = hash.split(':').collect();
    if partes.len() != 2 {
        bail!("Invalid hash format");
    }

    let salt = general_purpose::STANDARD.decode(partes[0])?;
    let stored_hash = general_purpose::STANDARD.decode(partes[1])?;

    let result = pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(10000).unwrap(),
        &salt,
        pwd.as_bytes(),
        &stored_hash,
    );

    Ok(result.is_ok())
}

pub fn derive_key(key: &[u8]) -> Result<Vec<u8>> {
    let salt = get_or_create_salt()?;

    let mut derived_key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(10000).unwrap(),
        &salt,
        key,
        &mut derived_key,
    );

    Ok(derived_key.to_vec())
}

fn get_or_create_salt() -> Result<Vec<u8>> {
    match read_salt() {
        Ok(salt) => Ok(salt),
        Err(_) => {
            let mut salt_bytes = [0u8; 16];
            SystemRandom::new()
                .fill(&mut salt_bytes)
                .map_err(|_| anyhow!("Error: Failed to generate salt"))?;

            save_salt(&salt_bytes)?;
            Ok(salt_bytes.to_vec())
        }
    }
}

fn read_salt() -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(0x80)
        .open(constantes::KEY_PATH)?;

    let mut key_size_bytes = [0u8; 4];
    file.read_exact(&mut key_size_bytes)?;
    let key_size = u32::from_le_bytes(key_size_bytes) as usize;

    file.seek(SeekFrom::Current(key_size as i64))?;

    let mut salt = vec![0u8; 16];
    let bytes_read = file.read(&mut salt)?;

    if bytes_read != 16 {
        bail!("Error: No salt found in key file or invalid salt size");
    }

    Ok(salt)
}

fn save_salt(salt: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(0x80)
        .open(constantes::KEY_PATH)?;

    let mut key_size_bytes = [0u8; 4];
    file.read_exact(&mut key_size_bytes)?;
    let key_size = u32::from_le_bytes(key_size_bytes) as usize;

    file.seek(SeekFrom::Start(4 + key_size as u64))?;
    file.write_all(salt)?;

    Ok(())
}
