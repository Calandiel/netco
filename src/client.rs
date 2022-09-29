use crate::cryptography::{self, encrypt, hash_string};
use crate::error::{ClientCreationError, ClientError};
use crate::packet::{ClientPacketTypes, ServerPacketTypes};
use crate::sequence_greater_than;
use crate::socket::Socket;
use nanorand::Rng;
use num_traits::FromPrimitive;
use std::collections::VecDeque;
use std::net::{SocketAddr, ToSocketAddrs};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub const MAX_NICKNANE_SIZE: usize = 750;

#[derive(Debug)]
pub enum ClientEvent {
	Connected,
	Disconnected(DisconnectReacton),
	Packet(Vec<u8>),
}
#[derive(Debug)]
pub enum DisconnectReacton {
	Timeout,
	WrongServerPassword,
	WrongAccountPassword,
	AccountAlreadyExists,
	AccountDoesNotExist,
	AccountInUse,
	TooManyPlayers,
	WrongVersion,
}

pub struct Client {
	state: ClientState,
	socket: Socket,
	server_addr: SocketAddr,
	client_salt: u32,
	server_salt: u32,
	protocol_version: u32,
	// cryptography
	nonce: u128,
	private_key: Option<EphemeralSecret>,
	public_key: PublicKey,
	shared_secret: Option<SharedSecret>,
	// credentials
	server_password: String,
	nickname: String,
	password: String,
	//
	last_seen: std::time::Instant,
	//
	new_account: bool,
	//
	messages: VecDeque<ClientEvent>,
	send_queue: VecDeque<ClientPacketTypes>,
	send_data_queue: VecDeque<Vec<u8>>,
	//
	encrypted_message_counter: u16,
	encrypted_send_queue: VecDeque<ClientPacketTypes>,
	encrypted_send_data_queue: VecDeque<Vec<u8>>,
	//
	reliable_message_counter: u16,
	reliable_send_queue: VecDeque<ClientPacketTypes>,
	reliable_send_data_queue: VecDeque<Vec<u8>>,
	// for receiving data:
	receive_encrypted_receive_message_counter: u16,
	receive_reliable_receive_message_counter: u16,
}
impl Client {
	/// Address to open for the client socket (should prolly be 0.0.0.0:port)
	pub fn new<A>(
		addr: A,
		server_addr: A,
		version: u32,
		server_password: String,
		nickname: String,
		password: String,
		new_account: bool,
	) -> Result<Client, ClientCreationError>
	where
		A: ToSocketAddrs,
	{
		let socket = Socket::new(addr)?;

		// client connection salts don't need to be cryptographically secure -- they're in plain light anyway
		let mut rng = nanorand::WyRand::new();
		let secret = EphemeralSecret::new(old_rand::rngs::OsRng);
		let public_key = PublicKey::from(&secret);

		let addr = server_addr
			.to_socket_addrs()?
			.next()
			.ok_or(ClientCreationError::NoServerAddress)?;

		Ok(Client {
			socket,
			state: ClientState::Connecting,
			server_addr: addr,
			client_salt: rng.generate(),
			server_salt: 0,
			private_key: Some(secret),
			shared_secret: None,
			public_key,
			protocol_version: version,
			nonce: 0,
			last_seen: std::time::Instant::now(),
			server_password,
			nickname,
			password,
			new_account,
			messages: Default::default(),
			send_queue: Default::default(),
			send_data_queue: Default::default(),
			encrypted_send_queue: Default::default(),
			encrypted_send_data_queue: Default::default(),
			encrypted_message_counter: 0,
			reliable_send_queue: Default::default(),
			reliable_send_data_queue: Default::default(),
			reliable_message_counter: 0,
			receive_encrypted_receive_message_counter: 0,
			receive_reliable_receive_message_counter: 0,
		})
	}

	pub fn disconnect(&mut self) -> Result<(), ClientError> {
		if let ClientState::Connected = self.state {
			self.encrypted_send_queue
				.push_back(ClientPacketTypes::Disconnect);
			self.service()?;
		}
		Ok(())
	}

	pub fn disconnect_and_delete_account(&mut self) -> Result<(), ClientError> {
		if let ClientState::Connected = self.state {
			self.encrypted_send_queue
				.push_back(ClientPacketTypes::DeleteAccount);
			self.service()?;
		}
		Ok(())
	}

	pub fn change_password(&mut self, new_password: String) -> Result<(), ClientError> {
		if let ClientState::Connected = self.state {
			self.encrypted_send_queue
				.push_back(ClientPacketTypes::ChangePassword);
			let new_pass = hash_string(&new_password);
			self.encrypted_send_data_queue
				.push_back(new_pass.to_owned().to_vec());
			self.service()?;
		}
		Ok(())
	}

	pub fn send_encrypted_packet(&mut self, data: Vec<u8>) {
		if let ClientState::Connected = self.state {
			self.encrypted_send_data_queue.push_back(data);
			self.encrypted_send_queue
				.push_back(ClientPacketTypes::EncryptedPacket);
		}
	}

	pub fn send_unreliable_unordered_packet(&mut self, data: Vec<u8>) {
		if let ClientState::Connected = self.state {
			self.send_queue
				.push_back(ClientPacketTypes::UnreliableUnordered);
			self.send_data_queue.push_back(data);
		}
	}

	pub fn send_reliable_ordered_packet(&mut self, data: Vec<u8>) {
		if let ClientState::Connected = self.state {
			self.reliable_send_data_queue.push_back(data);
			self.reliable_send_queue
				.push_back(ClientPacketTypes::ReliableOrdered);
		}
	}

	pub fn get_next_message(&mut self) -> Option<ClientEvent> {
		self.messages.pop_front()
	}

	pub fn service(&mut self) -> Result<(), ClientError> {
		let now = std::time::Instant::now();
		if crate::connection::TIMEOUT < (now - self.last_seen).as_millis() {
			match self.state {
				ClientState::Disconnected => {
					// nothing to do, we already disconnected...
				}
				_ => {
					self.state = ClientState::Disconnected;
					self.messages
						.push_back(ClientEvent::Disconnected(DisconnectReacton::Timeout));
				}
			}
			return Ok(());
		}

		// Protocol connection handling
		match self.state {
			ClientState::Disconnected => {
				// nothing to do
				return Ok(());
			}
			ClientState::Connecting => {
				// connecting...
				self.socket.clear();
				// packet type + salt, 1 + 4
				self.socket
					.write_salt_and_init(ClientPacketTypes::Greeting, self.client_salt)?;
				// protocol version 1 + 4 + 4
				let le_bytes = self.protocol_version.to_le_bytes();
				for b in le_bytes {
					self.socket.write_byte(b)?;
				}
				// public key 1 + 4 + 4 + 32
				let bytes = self.public_key.as_bytes();
				for b in bytes {
					self.socket.write_byte(*b)?;
				}
				// padding
				self.socket.pad();

				self.socket.send(self.server_addr)?;
			}
			ClientState::Authenticating => {
				self.socket.clear();
				// 1 + 4
				self.socket
					.write_salt_and_init(ClientPacketTypes::Login, self.client_salt)?;

				if self.new_account {
					self.socket.write_byte(1)?;
				} else {
					self.socket.write_byte(0)?;
				}

				//
				let mut payload = vec![];
				let ser_pass = hash_string(&self.server_password);
				let my_pass = hash_string(&self.password);
				let nickname = self.nickname.as_bytes();
				if nickname.len() < MAX_NICKNANE_SIZE {
				} else {
					return Err(ClientError::NicknameTooLong);
				}
				for b in ser_pass {
					payload.push(b);
				}
				for b in my_pass {
					payload.push(b);
				}
				for b in nickname {
					payload.push(*b);
				}
				encrypt(
					&mut payload,
					self.nonce,
					self.shared_secret
						.as_ref()
						.ok_or(ClientError::MissingEncryptionKey)?,
				)?;
				// Payload size
				let payload_size_bytes = (payload.len() as u32).to_le_bytes();
				for b in payload_size_bytes {
					self.socket.write_byte(b)?;
				}
				for b in payload {
					self.socket.write_byte(b)?;
				}

				self.socket.send(self.server_addr)?;
			}
			ClientState::Connected => {
				// First, send the client ping back to the server...
				self.socket.clear();
				self.socket
					.write_salt_and_init(ClientPacketTypes::Ping, self.client_salt)?; // 1 + 4
				let bytes = self.receive_encrypted_receive_message_counter.to_le_bytes();
				self.socket.write_byte(bytes[0])?;
				self.socket.write_byte(bytes[1])?; // 1 + 4 + 2
				let bytes = self.receive_reliable_receive_message_counter.to_le_bytes();
				self.socket.write_byte(bytes[0])?;
				self.socket.write_byte(bytes[1])?; // 1 + 4 + 2 + 16 + 2
				self.socket.send(self.server_addr)?;

				// In this state, we ought to handle packet scheduling
				while !self.send_queue.is_empty() {
					let pt = self.send_queue.pop_front().unwrap();
					match pt {
						ClientPacketTypes::Greeting
						| ClientPacketTypes::Login
						| ClientPacketTypes::Disconnect
						| ClientPacketTypes::DeleteAccount
						| ClientPacketTypes::ChangePassword
						| ClientPacketTypes::EncryptedPacket
						| ClientPacketTypes::ReliableOrdered
						| ClientPacketTypes::Ping => {
							// skip packets that can't be sent from this queue!
						}
						ClientPacketTypes::UnreliableUnordered => {
							//
							let data = self.send_data_queue.pop_front().unwrap();
							self.socket.clear();
							self.socket.write_salt_and_init(
								ClientPacketTypes::UnreliableUnordered,
								self.client_salt,
							)?; // 1 + 4
							for b in data {
								self.socket.write_byte(b)?;
							}
							self.socket.send(self.server_addr)?;
						}
					}
				}
				if !self.reliable_send_queue.is_empty() {
					let pt = self.reliable_send_queue.front().unwrap();
					match pt {
						ClientPacketTypes::Greeting
						| ClientPacketTypes::Login
						| ClientPacketTypes::Disconnect
						| ClientPacketTypes::ChangePassword
						| ClientPacketTypes::DeleteAccount
						| ClientPacketTypes::EncryptedPacket
						| ClientPacketTypes::UnreliableUnordered
						| ClientPacketTypes::Ping => {
							// skip packets that can't be sent from this queue!
						}
						ClientPacketTypes::ReliableOrdered => {
							//
							self.socket.clear();
							self.socket.write_salt_and_init(*pt, self.client_salt)?; // 1 + 4
							let bytes = self.reliable_message_counter.to_le_bytes();
							self.socket.write_byte(bytes[0])?;
							self.socket.write_byte(bytes[1])?; // 1 + 4 + 2
							let fr = self.reliable_send_data_queue.front().unwrap().clone();
							for b in fr {
								self.socket.write_byte(b)?;
							}
							self.socket.send(self.server_addr)?;
						}
					}
				}
				if !self.encrypted_send_queue.is_empty() {
					let pt = self.encrypted_send_queue.front().unwrap();
					match pt {
						ClientPacketTypes::Greeting
						| ClientPacketTypes::Login
						| ClientPacketTypes::UnreliableUnordered
						| ClientPacketTypes::ReliableOrdered
						| ClientPacketTypes::Ping => {
							// skip packets that can't be sent from this queue!
						}
						ClientPacketTypes::Disconnect | ClientPacketTypes::DeleteAccount => {
							//
							self.socket.clear();
							self.socket.write_salt_and_init(*pt, self.client_salt)?; // 1 + 4
							let bytes = self.encrypted_message_counter.to_le_bytes();
							self.socket.write_byte(bytes[0])?;
							self.socket.write_byte(bytes[1])?; // 1 + 4 + 2
							let mut bytes: Vec<u8> = bytes.to_owned().to_vec();
							for i in self.shared_secret.as_ref().unwrap().as_bytes().iter() {
								bytes.push(*i);
							}
							//
							let hashed = cryptography::hash_vector(&bytes);
							for b in hashed {
								self.socket.write_byte(b)?;
							} // 1 + 4 + 2 + 32
							self.socket.send(self.server_addr)?;
							//println!("{:?} -- {:?}", *pt, self.socket.get_data().1);
						}
						ClientPacketTypes::EncryptedPacket | ClientPacketTypes::ChangePassword => {
							self.socket.clear();
							self.socket.write_salt_and_init(*pt, self.client_salt)?;
							let bytes = self.encrypted_message_counter.to_le_bytes();
							self.socket.write_byte(bytes[0])?;
							self.socket.write_byte(bytes[1])?;
							let mut bytes: Vec<u8> = bytes.to_owned().to_vec();
							for i in self.shared_secret.as_ref().unwrap().as_bytes().iter() {
								bytes.push(*i);
							}
							//
							let hashed = cryptography::hash_vector(&bytes);
							for b in hashed {
								self.socket.write_byte(b)?;
							} // 1 + 4 + 2 + 32
							let mut fr = self.encrypted_send_data_queue.front().unwrap().clone();
							cryptography::encrypt(
								&mut fr,
								self.nonce,
								self.shared_secret.as_ref().unwrap(),
							)?;
							for b in fr {
								self.socket.write_byte(b)?;
							}
							self.socket.send(self.server_addr)?;
						}
					}
				}
			}
		}

		// Receive loop
		loop {
			//
			let res = self.socket.recv();

			match res {
				Ok(addr) => {
					//
					let (data, len) = self.socket.get_data();
					if len > 0 {
						let server_packet_type: Option<ServerPacketTypes> =
							FromPrimitive::from_u8(data[0]);
						if let Some(server_packet_type) = server_packet_type {
							match self.state {
								ClientState::Connecting => {
									if addr == self.server_addr {
										match server_packet_type {
											ServerPacketTypes::Greeting => {
												if len == 53 {
													//
													let server_salt = u32::from_le_bytes([
														data[1], data[2], data[3], data[4],
													]);
													let mut nonce_bytes = [0; 16];
													nonce_bytes[..16]
														.copy_from_slice(&data[5..(16 + 5)]);
													let nonce = u128::from_le_bytes(nonce_bytes);
													let mut public_key_bytes = [0; 32];
													public_key_bytes[..32]
														.copy_from_slice(&data[21..(32 + 21)]);
													let public_key =
														PublicKey::from(public_key_bytes);

													self.server_salt = server_salt;
													self.shared_secret = Some(
														self.private_key
															.take()
															.ok_or(
																ClientError::MissingEncryptionKey,
															)?
															.diffie_hellman(&public_key),
													);
													self.nonce = nonce;

													self.state = ClientState::Authenticating;
												}
											}
											ServerPacketTypes::BadProtocol => {
												self.state = ClientState::Disconnected;
												self.messages.push_back(ClientEvent::Disconnected(
													DisconnectReacton::WrongVersion,
												));
											}
											ServerPacketTypes::TooManyPlayers => {
												self.state = ClientState::Disconnected;
												self.messages.push_back(ClientEvent::Disconnected(
													DisconnectReacton::TooManyPlayers,
												));
											}
											_ => {
												//ignore other packets
											}
										}
									}
								}
								ClientState::Authenticating => {
									if len == 1 || len == 1 + 16 {
										if addr == self.server_addr {
											match server_packet_type {
												ServerPacketTypes::TooManyPlayers
												| ServerPacketTypes::WrongServerPassword
												| ServerPacketTypes::WrongAccountPassword
												| ServerPacketTypes::AccountExists
												| ServerPacketTypes::AccountDoesNotExist
												| ServerPacketTypes::AccountInUse => {
													self.state = ClientState::Disconnected;
												}
												ServerPacketTypes::LoginSuccess => {
													if len == 1 + 16 {
														self.state = ClientState::Connected;
														let mut nonce_bytes = [0; 16];
														nonce_bytes[..16]
															.copy_from_slice(&data[1..(16 + 1)]);
														self.nonce =
															u128::from_le_bytes(nonce_bytes);
													}
												}
												_ => {}
											}
											match server_packet_type {
												ServerPacketTypes::TooManyPlayers => {
													self.messages.push_back(
														ClientEvent::Disconnected(
															DisconnectReacton::TooManyPlayers,
														),
													);
												}
												ServerPacketTypes::WrongServerPassword => {
													self.messages.push_back(
														ClientEvent::Disconnected(
															DisconnectReacton::WrongServerPassword,
														),
													);
												}
												ServerPacketTypes::WrongAccountPassword => {
													self.messages.push_back(
														ClientEvent::Disconnected(
															DisconnectReacton::WrongAccountPassword,
														),
													);
												}
												ServerPacketTypes::AccountExists => {
													self.messages.push_back(
														ClientEvent::Disconnected(
															DisconnectReacton::AccountAlreadyExists,
														),
													);
												}
												ServerPacketTypes::AccountDoesNotExist => {
													self.messages.push_back(
														ClientEvent::Disconnected(
															DisconnectReacton::AccountDoesNotExist,
														),
													);
												}
												ServerPacketTypes::AccountInUse => {
													self.messages.push_back(
														ClientEvent::Disconnected(
															DisconnectReacton::AccountInUse,
														),
													);
												}
												ServerPacketTypes::LoginSuccess => {
													self.messages.push_back(ClientEvent::Connected);
												}
												_ => {}
											}
										}
									}
								}
								ClientState::Connected => {
									//
									match server_packet_type {
										ServerPacketTypes::Greeting
										| ServerPacketTypes::BadProtocol
										| ServerPacketTypes::TooManyPlayers
										| ServerPacketTypes::WrongServerPassword
										| ServerPacketTypes::WrongAccountPassword
										| ServerPacketTypes::AccountExists
										| ServerPacketTypes::AccountDoesNotExist
										| ServerPacketTypes::AccountInUse
										| ServerPacketTypes::LoginSuccess => {
											// nothing to do, these packets don't apply to this client state
										}
										ServerPacketTypes::Kick => todo!(),
										ServerPacketTypes::Ban => todo!(),
										ServerPacketTypes::Ping => {
											//
											if len == 1 + 4 + 2 + 16 + 2 {
												//
												let salt = u32::from_le_bytes([
													data[1], data[2], data[3], data[4],
												]);
												if self.server_salt == salt {
													self.last_seen = std::time::Instant::now();
													//sequence_greater_than
													let encrypted_sequence =
														u16::from_le_bytes([data[5], data[6]]);
													let reliable_sequence =
														u16::from_le_bytes([data[23], data[24]]);
													/*
													println!(
														"{} vs {}",
														self.encrypted_message_counter,
														encrypted_sequence
													);
													*/
													if sequence_greater_than(
														reliable_sequence,
														self.reliable_message_counter,
													) {
														self.reliable_send_queue.pop_front();
														self.reliable_send_data_queue.pop_front();
														self.reliable_message_counter =
															reliable_sequence;
													}
													if sequence_greater_than(
														encrypted_sequence,
														self.encrypted_message_counter,
													) {
														// An encrypted message "got through"!
														let new_nonce = u128::from_le_bytes([
															data[7],
															data[7 + 1],
															data[7 + 2],
															data[7 + 3],
															data[7 + 4],
															data[7 + 5],
															data[7 + 6],
															data[7 + 7],
															data[7 + 8],
															data[7 + 9],
															data[7 + 10],
															data[7 + 11],
															data[7 + 12],
															data[7 + 13],
															data[7 + 14],
															data[7 + 15],
														]);
														self.nonce = new_nonce;
														self.encrypted_message_counter =
															encrypted_sequence;
														match self
															.encrypted_send_queue
															.front()
															.unwrap()
														{
															ClientPacketTypes::EncryptedPacket
															| ClientPacketTypes::ChangePassword => {
																self.encrypted_send_data_queue
																	.pop_front();
															}
															_ => {}
														}
														self.encrypted_send_queue.pop_front();
														//println!("Poppin~");
													}
												}
											}
										}
										ServerPacketTypes::UnreliableUnordered => {
											if len >= 1 + 4 {
												//
												let salt = u32::from_le_bytes([
													data[1], data[2], data[3], data[4],
												]);
												if self.server_salt == salt {
													self.messages.push_back(ClientEvent::Packet(
														data[1 + 4..].to_vec(),
													));
												}
											}
										}
										ServerPacketTypes::ReliableOrdered => {
											if len >= 1 + 4 + 2 {
												//
												let salt = u32::from_le_bytes([
													data[1], data[2], data[3], data[4],
												]);
												if self.server_salt == salt {
													let counter =
														u16::from_le_bytes([data[5], data[6]]);
													if counter
														== self
															.receive_reliable_receive_message_counter
													{
														self.receive_reliable_receive_message_counter = self.receive_reliable_receive_message_counter.wrapping_add(1);
														self.messages.push_back(
															ClientEvent::Packet(
																data[1 + 4 + 2..].to_vec(),
															),
														);
													}
												}
											}
										}
										ServerPacketTypes::EncryptedPacket => todo!(), //
									}
								}
								ClientState::Disconnected => {
									// nothing to do
								}
							}
						}
					}
				}
				Err(_) => break,
			}
		}
		Ok(())
	}
}

enum ClientState {
	// Sending "greeting" packets
	Connecting,
	// Sending "login" packets
	Authenticating,
	// "in game"
	Connected,
	// For when something goes wrong or when we get kicked :c
	Disconnected,
}
