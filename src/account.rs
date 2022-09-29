use crate::cryptography;

pub struct Account {
	pub name: String,
	pub salt: u128,
	pub salted_password: Vec<u8>,
}
impl Account {
	pub fn salt_password(salt: u128, password: &mut Vec<u8>) {
		let salt_bytes = salt.to_le_bytes();
		for b in salt_bytes {
			password.push(b);
		}
		let v = cryptography::hash_vector(password);
		*password = v.to_vec();
	}
}
