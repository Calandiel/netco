use crate::error::{DecryptionError, EncryptionError};
use aes_gcm_siv::{
	aead::{AeadInPlace, KeyInit, OsRng},
	Aes256GcmSiv,
	Nonce, // Or `Aes128GcmSiv`
};
use x25519_dalek::SharedSecret;

/// Calculates the base nonce based on the shared key
pub fn derive_base_nonce(bytes: &[u8; 32]) -> u128 {
	use sha3::{Digest, Sha3_256};

	let mut hasher = Sha3_256::new();
	hasher.update(bytes);
	hasher.update(52372343_u32.to_le_bytes()); // this is prolly unnecessary
	let result = hasher.finalize();

	// Calculate the base nonce!
	let mut nonce_bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	for i in 0..16 {
		nonce_bytes[i] = result[i];
	}
	u128::from_le_bytes(nonce_bytes)
}

pub fn next_nonce(old_nonce: u128) -> u128 {
	use nanorand::{Rng, WyRand};
	use sha3::{Digest, Sha3_256};

	let mut rng = WyRand::new();
	let mut hasher = Sha3_256::new();
	hasher.update(old_nonce.to_le_bytes());
	hasher.update(rng.generate::<u128>().to_le_bytes()); // this is prolly unnecessary
	let result = hasher.finalize();

	// Calculate the base nonce!
	let mut nonce_bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	for i in 0..16 {
		nonce_bytes[i] = result[i];
	}
	u128::from_le_bytes(nonce_bytes)
}

///
pub fn hash_string(st: &String) -> [u8; 32] {
	use sha3::{Digest, Sha3_256};
	let mut hasher = Sha3_256::new();
	hasher.update(st);
	hasher.update(52372343_u32.to_le_bytes()); // this is prolly unnecessary
	let result = hasher.finalize();
	let mut ret = [0; 32];
	for i in 0..32 {
		ret[i] = result[i]
	}
	ret
}

pub fn hash_vector(st: &Vec<u8>) -> [u8; 32] {
	use sha3::{Digest, Sha3_256};
	let mut hasher = Sha3_256::new();
	hasher.update(st);
	hasher.update(52372343_u32.to_le_bytes()); // this is prolly unnecessary
	let result = hasher.finalize();
	let mut ret = [0; 32];
	for i in 0..32 {
		ret[i] = result[i]
	}
	ret
}

///
pub fn encrypt(
	payload: &mut Vec<u8>, // taking a vec because the encryption library requests one...
	nonce_number: u128,
	shared_secret: &SharedSecret,
) -> Result<(), EncryptionError> {
	let nonce_bytes = nonce_number.to_le_bytes();
	let nonce = Nonce::from_slice(&nonce_bytes[..12]);
	let mut key = Aes256GcmSiv::generate_key(&mut OsRng);
	let sl = key.as_mut_slice();
	sl[..32].copy_from_slice(&shared_secret.as_bytes()[..32]);
	let cipher = Aes256GcmSiv::new(&key);
	if let Ok(()) = cipher.encrypt_in_place(nonce, &[], payload) {
		//
	} else {
		return Err(EncryptionError::EncryptionFailure);
	};

	Ok(())
}

///
pub fn decrypt(
	payload: &mut Vec<u8>, // taking a vec because the encryption library requests one...
	nonce_number: u128,
	shared_secret: &SharedSecret,
) -> Result<(), DecryptionError> {
	let nonce_bytes = nonce_number.to_le_bytes();
	let nonce = Nonce::from_slice(&nonce_bytes[..12]);
	let mut key = Aes256GcmSiv::generate_key(&mut OsRng);
	let sl = key.as_mut_slice();
	sl[..32].copy_from_slice(&shared_secret.as_bytes()[..32]);
	let cipher = Aes256GcmSiv::new(&key);
	if let Ok(()) = cipher.decrypt_in_place(nonce, &[], payload) {
		//
	} else {
		return Err(DecryptionError::DecryptionFailure);
	};

	Ok(())
}
