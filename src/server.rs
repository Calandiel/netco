use crate::account::Account;
use crate::connection::{Connection, ConnectionIdentifier, ConnectionState};

use crate::cryptography::{self, next_nonce};
use crate::error::{ServerCreationError, ServerError};
use crate::packet::{ClientPacketTypes, ServerPacketTypes};
use crate::sequence_greater_than;
use crate::socket::Socket;
use nanorand::{Rng, WyRand};
use num_traits::FromPrimitive;
use std::collections::VecDeque;
use std::net::{SocketAddr, ToSocketAddrs};
use x25519_dalek::PublicKey;

#[derive(Debug)]
pub enum ServerEvent {
	PlayerConnected(String),
	PlayerDisconnected(String),
	AccountRemoved(String),
	Packet((String, Vec<u8>)),
}

pub struct Server {
	socket: Socket,
	password: [u8; 32], // server password, hashed
	connections: ahash::AHashMap<ConnectionIdentifier, Connection>,
	accounts: ahash::AHashMap<String, Account>,
	version: u32,
	max_players: u32,
	used_accounts: ahash::AHashMap<String, ConnectionIdentifier>,
	messages: VecDeque<ServerEvent>,
}
impl Server {
	/// On success, returns the created socket, in non blocking state
	pub fn new<A>(
		addr: A,
		password: String,
		version: u32,
		max_players: u32,
	) -> Result<Server, ServerCreationError>
	where
		A: ToSocketAddrs,
	{
		let socket = Socket::new(addr)?;
		let password = crate::cryptography::hash_string(&password);
		Ok(Server {
			socket,
			password,
			connections: Default::default(),
			version,
			max_players,
			accounts: Default::default(),
			used_accounts: Default::default(),
			messages: Default::default(),
		})
	}

	pub fn get_next_message(&mut self) -> Option<ServerEvent> {
		self.messages.pop_front()
	}

	fn get_identifier(&self, addr: SocketAddr) -> Option<ConnectionIdentifier> {
		let (data, len) = self.socket.get_data();
		if len >= 5 {
			let client_salt = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
			Some(ConnectionIdentifier { client_salt, addr })
		} else {
			None
		}
	}

	fn get_packet_author(&self, addr: SocketAddr) -> Option<&Connection> {
		self.connections.get(&self.get_identifier(addr)?)
	}

	fn get_packet_author_mut(&mut self, addr: SocketAddr) -> Option<&mut Connection> {
		self.connections.get_mut(&self.get_identifier(addr)?)
	}

	fn mark_as_logged_in(&mut self, addr: SocketAddr, nick: String) {
		self.get_packet_author_mut(addr).unwrap().used_account = Some(nick.clone());
		self.used_accounts
			.insert(nick.clone(), self.get_identifier(addr).unwrap());
		self.messages.push_back(ServerEvent::PlayerConnected(nick));
	}

	fn mark_as_logged_out(&mut self, addr: SocketAddr, nick: String) {
		self.get_packet_author_mut(addr).unwrap().used_account = None;
		self.used_accounts.remove(&nick);
		self.messages
			.push_back(ServerEvent::PlayerDisconnected(nick));
		self.connections.remove(&ConnectionIdentifier {
			addr,
			client_salt: self.get_packet_author(addr).unwrap().client_salt,
		});
		//println!("!!");
	}

	/*
	pub fn send_encrypted_packet(&mut self, recipient: &String, data: Vec<u8>) {
		if let Some(v) = self.used_accounts.get(recipient) {
			if let Some(conn) = self.get_packet_author_mut(v.addr) {
				if let ConnectionState::Verified = conn.state {
					conn.encrypted_send_data_queue.push_back(data);
					conn.encrypted_send_queue
						.push_back(ServerPacketTypes::EncryptedPacket);
				}
			}
		}
	}
	*/

	pub fn send_unreliable_unordered_packet(&mut self, recipient: &String, data: Vec<u8>) {
		if let Some(v) = self.used_accounts.get(recipient) {
			if let Some(conn) = self.get_packet_author_mut(v.addr) {
				if let ConnectionState::Verified = conn.state {
					conn.send_queue
						.push_back(ServerPacketTypes::UnreliableUnordered);
					conn.send_data_queue.push_back(data);
				}
			}
		}
	}

	pub fn send_reliable_ordered_packet(&mut self, recipient: &String, data: Vec<u8>) {
		if let Some(v) = self.used_accounts.get(recipient) {
			if let Some(conn) = self.get_packet_author_mut(v.addr) {
				if let ConnectionState::Verified = conn.state {
					conn.reliable_send_data_queue.push_back(data);
					conn.reliable_send_queue
						.push_back(ServerPacketTypes::ReliableOrdered);
				}
			}
		}
	}

	pub fn service(&mut self) -> Result<(), ServerError> {
		// Check for timeouts
		let now = std::time::Instant::now();
		self.connections.retain(|_, v| {
			let time = (now - v.last_seen).as_millis();
			if time > crate::connection::TIMEOUT {
				if let Some(nick) = v.used_account.take() {
					self.used_accounts.remove(&nick);
					self.messages
						.push_back(ServerEvent::PlayerDisconnected(nick));
				}
				false
			} else {
				true
			}
		});
		// Send packets to all connected clients!
		for (identifier, con) in &mut self.connections {
			if let ConnectionState::Verified = con.state {
				self.socket.clear();
				self.socket
					.write_salt_and_init(ServerPacketTypes::Ping, con.server_salt)?; // 1 + 4
				let bytes = con.encrypted_receive_message_counter.to_le_bytes();
				self.socket.write_byte(bytes[0])?;
				self.socket.write_byte(bytes[1])?; // 1 + 4 + 2
				let bytes = con.base_nonce.to_le_bytes();
				for b in bytes {
					self.socket.write_byte(b)?;
				} // 1 + 4 + 2 + 16
				let bytes = con.reliable_receive_message_counter.to_le_bytes();
				self.socket.write_byte(bytes[0])?;
				self.socket.write_byte(bytes[1])?; // 1 + 4 + 2 + 16 + 2
				self.socket.send(identifier.addr)?;

				// After sending the ping, send the scheduled packets!
				while !con.send_queue.is_empty() {
					let pt = con.send_queue.pop_front().unwrap();
					match pt {
						ServerPacketTypes::Greeting
						| ServerPacketTypes::BadProtocol
						| ServerPacketTypes::TooManyPlayers
						| ServerPacketTypes::WrongServerPassword
						| ServerPacketTypes::WrongAccountPassword
						| ServerPacketTypes::AccountExists
						| ServerPacketTypes::AccountDoesNotExist
						| ServerPacketTypes::AccountInUse
						| ServerPacketTypes::LoginSuccess
						| ServerPacketTypes::Kick
						| ServerPacketTypes::Ban
						| ServerPacketTypes::ReliableOrdered
						| ServerPacketTypes::EncryptedPacket
						| ServerPacketTypes::Ping => {
							// these packets cant be sent from this queue...
						}
						ServerPacketTypes::UnreliableUnordered => {
							//
							let data = con.send_data_queue.pop_front().unwrap();
							self.socket.clear();
							self.socket.write_salt_and_init(
								ServerPacketTypes::UnreliableUnordered,
								con.server_salt,
							)?; // 1 + 4
							for b in data {
								self.socket.write_byte(b)?;
							}
							self.socket.send(identifier.addr)?;
						}
					}
				}
				if !con.reliable_send_queue.is_empty() {
					let pt = con.reliable_send_queue.front().unwrap();
					match pt {
						ServerPacketTypes::Greeting
						| ServerPacketTypes::BadProtocol
						| ServerPacketTypes::TooManyPlayers
						| ServerPacketTypes::WrongServerPassword
						| ServerPacketTypes::WrongAccountPassword
						| ServerPacketTypes::AccountExists
						| ServerPacketTypes::AccountDoesNotExist
						| ServerPacketTypes::AccountInUse
						| ServerPacketTypes::LoginSuccess
						| ServerPacketTypes::Kick
						| ServerPacketTypes::Ban
						| ServerPacketTypes::UnreliableUnordered
						| ServerPacketTypes::EncryptedPacket
						| ServerPacketTypes::Ping => {
							// these packets cant be sent from this queue...
						}
						ServerPacketTypes::ReliableOrdered => {
							self.socket.clear();
							self.socket.write_salt_and_init(*pt, con.server_salt)?; // 1 + 4
							let bytes = con.reliable_message_counter.to_le_bytes();
							self.socket.write_byte(bytes[0])?;
							self.socket.write_byte(bytes[1])?; // 1 + 4 + 2
							let fr = con.reliable_send_data_queue.front().unwrap().clone();
							for b in fr {
								self.socket.write_byte(b)?;
							}
							self.socket.send(identifier.addr)?;
						}
					}
				}
			}
		}
		//
		loop {
			//
			let res = self.socket.recv();
			match res {
				Ok(addr) => {
					//
					let (data, len) = self.socket.get_data();
					// ALL messages of our protocol ought to be AT LEAST 1 byte long.
					if len >= 5 {
						//
						let bb = data[0];
						let client_packet_type: Option<ClientPacketTypes> =
							FromPrimitive::from_u8(bb);
						let client_salt = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);

						if let Some(client_packet_type) = client_packet_type {
							match client_packet_type {
								ClientPacketTypes::Greeting => {
									//
									if len == 1000 {
										//
										let protocol_version = u32::from_le_bytes([
											data[5], data[6], data[7], data[8],
										]);
										if self.version == protocol_version {
											// The version is correct. Check if the connection already exists...
											let identifier =
												ConnectionIdentifier { addr, client_salt };
											if let Some(conn) = self.connections.get(&identifier) {
												if let ConnectionState::Unverified = conn.state {
													//
													self.socket.clear();
													// 1 + 4 = 5
													self.socket.write_salt_and_init(
														ServerPacketTypes::Greeting,
														conn.server_salt,
													)?;
													// 1 + 4 + 16 = 21
													let nonce_bytes = conn.base_nonce.to_le_bytes();
													for b in nonce_bytes {
														self.socket.write_byte(b)?;
													}
													// 1 + 4 + 16 + 32 = 53
													let server_public_key =
														conn.public_key.as_bytes();
													for b in server_public_key {
														self.socket.write_byte(*b)?;
													}
													self.socket.send(addr)?;
												} else {
													self.socket.clear();
													self.socket
														.init(ServerPacketTypes::AccountInUse)?;
													self.socket.send(addr)?;
												}
											} else {
												if self.connections.len()
													>= self.max_players as usize
												{
													self.socket.clear();
													self.socket
														.init(ServerPacketTypes::TooManyPlayers)?;
													self.socket.send(addr)?;
												} else {
													// connection doesn't exist!
													let mut bytes = [0; 32];
													bytes[..32].copy_from_slice(&data[9..(9 + 32)]);
													let their_public_key = PublicKey::from(bytes);
													// server connection salts don't need to be cryptographically secure -- they're in plain light anyway
													let mut rng = nanorand::WyRand::new();
													self.connections.insert(
														identifier,
														Connection::new(
															addr,
															client_salt,
															rng.generate::<u32>(),
															&their_public_key,
														),
													);
												}
											}
										} else {
											// wrong protocol version -- tell the client about it
											self.socket.clear();
											self.socket.init(ServerPacketTypes::BadProtocol)?;
											self.socket.send(addr)?;
										}
									}
								}
								ClientPacketTypes::Login => {
									if len >= 1 + 4 + 32 + 32 + 4 + 1 {
										if let Some(con) = self.get_packet_author(addr) {
											//
											let new_account = data[5] != 0;
											let payload_size = u32::from_le_bytes([
												data[6], data[7], data[8], data[9],
											]);
											let payload = &data[10..(10 + payload_size as usize)];
											let mut payload_vec = payload.to_owned();
											if crate::cryptography::decrypt(
												&mut payload_vec,
												con.base_nonce,
												&con.shared_key,
											)
											.is_ok()
											{
												let server_password = &payload_vec[..32];
												let password = &payload_vec[32..(2 * 32)];
												let nickname = &payload_vec[(2 * 32)..];
												// First, check server password
												let password_ok = {
													let mut r = true;
													for x in 0..32 {
														if server_password[x] != self.password[x] {
															r = false;
															break;
														}
													}
													r
												};

												if password_ok {
													if let Ok(nick) =
														String::from_utf8(nickname.to_owned())
													{
														if new_account {
															// new account creation
															if let Some(_) =
																self.accounts.get(&nick)
															{
																let conn = self
																	.get_packet_author_mut(addr)
																	.unwrap();
																if let Some(_) = &conn.used_account
																{
																	conn.state =
																		ConnectionState::Verified;
																	// Update nonce
																	conn.base_nonce =
																		next_nonce(conn.base_nonce);
																	let nonce_bytes = conn
																		.base_nonce
																		.to_le_bytes();
																	self.socket.clear();
																	self.socket.init(
																ServerPacketTypes::LoginSuccess,
																	)?;
																	for b in nonce_bytes {
																		self.socket
																			.write_byte(b)?;
																	}
																	self.socket.send(addr)?;
																} else {
																	// account exists!
																	self.socket.clear();
																	self.socket.init(
																ServerPacketTypes::AccountExists,
																	)?;
																	self.socket.send(addr)?;
																}
															} else {
																// account doesn't exist!
																let salt = WyRand::new()
																	.generate::<u128>();
																let mut pass_vec: Vec<u8> =
																	password.to_owned();
																Account::salt_password(
																	salt,
																	&mut pass_vec,
																);
																self.accounts.insert(
																	nick.clone(),
																	Account {
																		name: nick.clone(),
																		salt,
																		salted_password: pass_vec,
																	},
																);
																self.mark_as_logged_in(addr, nick);
															}
														} else {
															// a log-in attempt
															if self.accounts.get(&nick).is_some() {
																let conn = self
																	.get_packet_author_mut(addr)
																	.unwrap();
																if conn.used_account.is_some() {
																	conn.state =
																		ConnectionState::Verified;
																	// Update nonce
																	conn.base_nonce =
																		next_nonce(conn.base_nonce);
																	let nonce_bytes = conn
																		.base_nonce
																		.to_le_bytes();
																	self.socket.clear();
																	self.socket.init(
																		ServerPacketTypes::LoginSuccess,
																	)?;
																	for b in nonce_bytes {
																		self.socket
																			.write_byte(b)?;
																	}
																	self.socket.send(addr)?;
																} else {
																	if let Some(u) = &self
																		.used_accounts
																		.get(&nick)
																	{
																		if **u
																			== self
																				.get_identifier(
																					addr,
																				)
																				.expect("Suspicious identifier!")
																		{
																			panic!("This state should never happen!");
																		} else {
																			//
																			self.socket.clear();
																			self.socket.init(
																				ServerPacketTypes::AccountInUse,
																			)?;
																			self.socket
																				.send(addr)?;
																		}
																	} else {
																		// Check player password
																		self.mark_as_logged_in(
																			addr, nick,
																		);
																	}
																}
															} else {
																self.socket.clear();
																self.socket.init(
																ServerPacketTypes::AccountDoesNotExist,
																	)?;
																self.socket.send(addr)?;
															}
														}
													} else {
														// nickname parsing error
													}
												} else {
													// wrong server password
													self.socket.clear();
													self.socket.init(
														ServerPacketTypes::WrongServerPassword,
													)?;
													self.socket.send(addr)?;
												}
											} else {
												// encryption was botched
											}
										}
									}
								}
								ClientPacketTypes::DeleteAccount
								| ClientPacketTypes::Disconnect => {
									//
									if len == 1 + 4 + 2 + 32 {
										//println!("A");
										let identifier = ConnectionIdentifier { addr, client_salt };
										if let Some(conn) = self.connections.get_mut(&identifier) {
											//println!("B");
											if let ConnectionState::Verified = conn.state {
												//println!("C");
												if let Some(nick) = &conn.used_account {
													let counter = u16::from_le_bytes([
														data[1 + 4],
														data[1 + 4 + 1],
													]);
													if counter
														== conn.encrypted_receive_message_counter
													{
														//println!("D");
														let bytes = conn
															.encrypted_receive_message_counter
															.to_le_bytes();
														let mut bytes: Vec<u8> =
															bytes.to_owned().to_vec();
														for i in conn.shared_key.as_bytes().iter() {
															bytes.push(*i);
														}
														// Verify the author of the message
														let hashed =
															cryptography::hash_vector(&bytes);
														let mut check = true;
														for i in 0..32 {
															if hashed[i] != data[1 + 4 + 2 + i] {
																check = false;
																break;
															}
														}
														if check {
															conn.base_nonce =
																next_nonce(conn.base_nonce);
															conn.encrypted_receive_message_counter = conn
																.encrypted_receive_message_counter
																.wrapping_add(1);
															//println!("{}", conn.encrypted_message_counter);
															if let ClientPacketTypes::DeleteAccount =
															client_packet_type
														{
															self.accounts.remove(nick);
															self.messages.push_back(
																ServerEvent::AccountRemoved(
																	nick.clone(),
																),
															);
														}
															let nn = nick.clone();
															self.mark_as_logged_out(addr, nn);
														}
													}
												}
											}
										}
									}
								}
								ClientPacketTypes::ChangePassword => {
									//
									if len == 1 + 4 + 2 + 32 + 48 {
										//println!("A");
										let identifier = ConnectionIdentifier { addr, client_salt };
										if let Some(conn) = self.connections.get_mut(&identifier) {
											//println!("B");
											if let ConnectionState::Verified = conn.state {
												//println!("C");
												if let Some(nick) = &conn.used_account {
													let counter = u16::from_le_bytes([
														data[1 + 4],
														data[1 + 4 + 1],
													]);
													if counter
														== conn.encrypted_receive_message_counter
													{
														//
														let bytes = conn
															.encrypted_receive_message_counter
															.to_le_bytes();
														let mut bytes: Vec<u8> =
															bytes.to_owned().to_vec();
														for i in conn.shared_key.as_bytes().iter() {
															bytes.push(*i);
														}
														// Verify the author of the message
														let hashed =
															cryptography::hash_vector(&bytes);
														let mut check = true;
														for i in 0..32 {
															if hashed[i] != data[1 + 4 + 2 + i] {
																check = false;
																break;
															}
														}
														if check {
															let mut vv =
																(&data[1 + 4 + 2 + 32..]).to_vec();
															if cryptography::decrypt(
																&mut vv,
																conn.base_nonce,
																&conn.shared_key,
															)
															.is_ok()
															{
																//
																conn.base_nonce =
																	next_nonce(conn.base_nonce);
																conn.encrypted_receive_message_counter =
																	conn.encrypted_receive_message_counter
																		.wrapping_add(1);
																let acc = self
																	.accounts
																	.get_mut(nick)
																	.unwrap();
																Account::salt_password(
																	acc.salt, &mut vv,
																);
																acc.salted_password = vv;
															}
														}
													}
												}
											}
										}
									}
								}
								ClientPacketTypes::EncryptedPacket => {
									//
									if len >= 1 + 4 + 2 + 32 {
										//println!("A");
										let identifier = ConnectionIdentifier { addr, client_salt };
										if let Some(conn) = self.connections.get_mut(&identifier) {
											//println!("B");
											if let ConnectionState::Verified = conn.state {
												//println!("C");
												if let Some(nick) = &conn.used_account {
													let counter = u16::from_le_bytes([
														data[1 + 4],
														data[1 + 4 + 1],
													]);
													if counter
														== conn.encrypted_receive_message_counter
													{
														//
														let bytes = conn
															.encrypted_receive_message_counter
															.to_le_bytes();
														let mut bytes: Vec<u8> =
															bytes.to_owned().to_vec();
														for i in conn.shared_key.as_bytes().iter() {
															bytes.push(*i);
														}
														// Verify the author of the message
														let hashed =
															cryptography::hash_vector(&bytes);
														let mut check = true;
														for i in 0..32 {
															if hashed[i] != data[1 + 4 + 2 + i] {
																check = false;
																break;
															}
														}
														if check {
															let mut vv =
																(&data[1 + 4 + 2 + 32..]).to_vec();
															if cryptography::decrypt(
																&mut vv,
																conn.base_nonce,
																&conn.shared_key,
															)
															.is_ok()
															{
																//
																conn.base_nonce =
																	next_nonce(conn.base_nonce);
																conn.encrypted_receive_message_counter =
																	conn.encrypted_receive_message_counter
																		.wrapping_add(1);
																self.messages.push_back(
																	ServerEvent::Packet((
																		nick.clone(),
																		vv,
																	)),
																)
															}
														}
													}
												}
											}
										}
									}
								}
								ClientPacketTypes::UnreliableUnordered => {
									if len >= 1 + 4 {
										//println!("A");
										let identifier = ConnectionIdentifier { addr, client_salt };
										if let Some(conn) = self.connections.get_mut(&identifier) {
											//println!("B");
											if let ConnectionState::Verified = conn.state {
												//println!("C");
												if let Some(nick) = &conn.used_account {
													let bytes = data[1 + 4..].to_owned().to_vec();
													self.messages.push_back(ServerEvent::Packet((
														nick.clone(),
														bytes,
													)));
												}
											}
										}
									}
								}
								ClientPacketTypes::ReliableOrdered => {
									if len >= 1 + 4 + 2 {
										//
										let identifier = ConnectionIdentifier { addr, client_salt };
										if let Some(conn) = self.connections.get_mut(&identifier) {
											//println!("B");
											if let ConnectionState::Verified = conn.state {
												//println!("C");
												if let Some(nick) = &conn.used_account {
													let counter = u16::from_le_bytes([
														data[1 + 4],
														data[1 + 4 + 1],
													]);
													if counter
														== conn.reliable_receive_message_counter
													{
														conn.reliable_receive_message_counter =
															conn.reliable_receive_message_counter
																.wrapping_add(1);
														let bytes =
															data[1 + 4 + 2..].to_owned().to_vec();
														self.messages.push_back(
															ServerEvent::Packet((
																nick.clone(),
																bytes,
															)),
														);
													}
												}
											}
										}
									}
								}
								ClientPacketTypes::Ping => {
									if len >= 1 + 4 + 2 + 2 {
										//
										let identifier = ConnectionIdentifier { addr, client_salt };
										if let Some(conn) = self.connections.get_mut(&identifier) {
											//println!("B");
											if let ConnectionState::Verified = conn.state {
												//println!("C");
												if conn.used_account.is_some() {
													conn.last_seen = std::time::Instant::now();
													let encrypted_counter = u16::from_le_bytes([
														data[1 + 4],
														data[1 + 4 + 1],
													]);
													let reliable_counter = u16::from_le_bytes([
														data[1 + 4 + 2],
														data[1 + 4 + 3],
													]);

													if sequence_greater_than(
														encrypted_counter,
														conn.encrypted_message_counter,
													) {
														conn.encrypted_send_queue.pop_front();
														conn.encrypted_send_data_queue.pop_front();
														conn.encrypted_message_counter =
															encrypted_counter;
													}
													if sequence_greater_than(
														reliable_counter,
														conn.reliable_message_counter,
													) {
														conn.reliable_send_queue.pop_front();
														conn.reliable_send_data_queue.pop_front();
														conn.reliable_message_counter =
															reliable_counter;
													}
												}
											}
										}
									}
								}
							}
						} else {
							// nothing to do, invalid packet
						}
					} else {
						// ignore the packet, it's literally useless
					}
				}
				Err(_) => break, // all messages received!
			}
		}

		Ok(())
	}
}
