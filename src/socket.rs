use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

use num_traits::ToPrimitive;

use crate::{error::PacketWriteError, MAX_PACKET_SIZE};

#[derive(Debug)]
pub struct Socket {
	socket: UdpSocket,
	buffer_size: usize,
	buffer: [u8; MAX_PACKET_SIZE],
}
impl Socket {
	/// On success, returns the created socket, in non blocking state
	pub fn new<A>(addr: A) -> std::io::Result<Socket>
	where
		A: ToSocketAddrs,
	{
		let socket = UdpSocket::bind(addr)?;
		socket.set_nonblocking(true)?;
		Ok(Socket {
			socket,
			buffer_size: 0,
			buffer: [0; MAX_PACKET_SIZE],
		})
	}

	/// On success, returns the number of bytes sent.
	pub fn send<A>(&self, addr: A) -> std::io::Result<usize>
	where
		A: ToSocketAddrs,
	{
		self.socket.send_to(&self.buffer[..self.buffer_size], addr)
	}

	/// On success, receives a single packet and returns the socket.
	/// Writes the buffer on the socket struct.
	/// Can fail when there are no packets to receive.
	pub fn recv(&mut self) -> std::io::Result<SocketAddr> {
		let (received_size, socket_addr) = self.socket.recv_from(&mut self.buffer)?;
		self.buffer_size = received_size;
		Ok(socket_addr)
	}

	///
	pub fn clear(&mut self) {
		self.buffer_size = 0;
	}

	///
	pub fn get_data(&self) -> (&[u8], usize) {
		(&self.buffer[..self.buffer_size], self.buffer_size)
	}

	///
	pub fn init<T>(&mut self, packet_type: T) -> Result<(), PacketWriteError>
	where
		T: ToPrimitive,
	{
		let p = if let Some(p) = ToPrimitive::to_u8(&packet_type) {
			p
		} else {
			return Err(PacketWriteError::PacketTypeError);
		};
		self.write_byte(p)?;
		Ok(())
	}
	///
	pub fn write_salt_and_init<T>(
		&mut self,
		packet_type: T,
		salt: u32,
	) -> Result<(), PacketWriteError>
	where
		T: ToPrimitive,
	{
		self.init(packet_type)?;
		let le_bytes = salt.to_le_bytes();
		for b in le_bytes {
			self.write_byte(b)?;
		}
		Ok(())
	}

	///
	pub fn write_byte(&mut self, byte: u8) -> Result<(), PacketWriteError> {
		if self.buffer_size < MAX_PACKET_SIZE {
			self.buffer[self.buffer_size] = byte;
			self.buffer_size += 1;
			Ok(())
		} else {
			Err(PacketWriteError::OutOfBounds)
		}
	}

	///
	pub fn pad(&mut self) {
		self.buffer_size = MAX_PACKET_SIZE;
	}
}
