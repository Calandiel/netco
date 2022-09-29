use std::{collections::VecDeque, net::SocketAddr};

use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::{cryptography::derive_base_nonce, packet::ServerPacketTypes};

pub const TIMEOUT: u128 = 2500; // in ms (1k ms = 1 s)

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct ConnectionIdentifier {
	pub addr: SocketAddr,
	pub client_salt: u32,
}

/// This struct represents connections on the server side.
pub struct Connection {
	// Server and client salts are used to recognize connections.
	// This way we'll have cleaner disconnects because one IP/port pair won't match to the same connection.
	pub addr: SocketAddr,
	pub client_salt: u32,
	pub server_salt: u32, // server salts are stored per connection so that each connection has an unique one which makes hijacking of packets for new clients more difficult (TODO: we use a non cryptographically secure rng for this, is this okay? Because it probably isn't okay since it's happening server side and clients know the salts they receive...)
	// cryptography
	pub public_key: PublicKey,
	pub shared_key: SharedSecret,
	pub base_nonce: u128,
	//
	pub connection_start: std::time::Instant, // this value is used to detect abnormaly long timeouts
	pub last_seen: std::time::Instant,        // this value is used to detect timeouts
	//
	pub state: ConnectionState,
	//
	pub used_account: Option<String>,
	//
	pub encrypted_receive_message_counter: u16,
	pub reliable_receive_message_counter: u16,
	// for sending data
	//
	pub send_queue: VecDeque<ServerPacketTypes>,
	pub send_data_queue: VecDeque<Vec<u8>>,
	//
	pub encrypted_message_counter: u16,
	pub encrypted_send_queue: VecDeque<ServerPacketTypes>,
	pub encrypted_send_data_queue: VecDeque<Vec<u8>>,
	//
	pub reliable_message_counter: u16,
	pub reliable_send_queue: VecDeque<ServerPacketTypes>,
	pub reliable_send_data_queue: VecDeque<Vec<u8>>,
}
impl Connection {
	pub fn new(
		addr: SocketAddr,
		client_salt: u32,
		server_salt: u32,
		their_public: &PublicKey,
	) -> Connection {
		let secret = EphemeralSecret::new(old_rand::rngs::OsRng);
		let public_key = PublicKey::from(&secret);
		let shared_key = secret.diffie_hellman(their_public);
		let base_nonce = derive_base_nonce(shared_key.as_bytes());

		Connection {
			addr,
			public_key,
			shared_key,
			base_nonce,
			connection_start: std::time::Instant::now(),
			last_seen: std::time::Instant::now(),
			state: ConnectionState::Unverified,
			used_account: None,
			client_salt,
			server_salt,
			encrypted_receive_message_counter: 0,
			reliable_receive_message_counter: 0,
			send_queue: Default::default(),
			send_data_queue: Default::default(),
			encrypted_send_queue: Default::default(),
			encrypted_send_data_queue: Default::default(),
			encrypted_message_counter: 0,
			reliable_send_queue: Default::default(),
			reliable_send_data_queue: Default::default(),
			reliable_message_counter: 0,
		}
	}
}
#[derive(Debug, Copy, Clone)]
pub enum ConnectionState {
	Unverified, // before we verify the server password
	Verified,   // after we verify the passwords
}
