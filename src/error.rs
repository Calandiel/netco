use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerCreationError {
	#[error("error while parsing address: {source}")]
	AddressParseError {
		#[from]
		source: std::io::Error,
	},
	#[error("unknown")]
	Unknown,
}

#[derive(Error, Debug)]
pub enum ClientCreationError {
	#[error("error while parsing address: {source}")]
	AddressParseError {
		#[from]
		source: std::io::Error,
	},
	#[error("server address is missing")]
	NoServerAddress,
	#[error("unknown")]
	Unknown,
}

#[derive(Error, Debug)]
pub enum EncryptionError {
	#[error("encryption failure")]
	EncryptionFailure,
	#[error("unknown")]
	Unknown,
}

#[derive(Error, Debug)]
pub enum DecryptionError {
	#[error("decryption failure")]
	DecryptionFailure,
	#[error("unknown")]
	Unknown,
}

#[derive(Error, Debug)]
pub enum PacketWriteError {
	#[error("too many bytes added to the packet")]
	OutOfBounds,
	#[error("unknown packet type")]
	PacketTypeError,
	#[error("unknown")]
	Unknown,
}

#[derive(Error, Debug)]
pub enum ServerError {
	#[error("error while interacting with a socket: {source}")]
	SocketIoError {
		#[from]
		source: std::io::Error,
	},
	#[error("packed write error: {source}")]
	PacketWriteError {
		#[from]
		source: PacketWriteError,
	},
	#[error("unknown")]
	Unknown,
}

#[derive(Error, Debug)]
pub enum ClientError {
	#[error("nickname is too long")]
	NicknameTooLong,
	#[error("error while interacting with a socket: {source}")]
	SocketIoError {
		#[from]
		source: std::io::Error,
	},
	#[error("the client is missing encryption keys")]
	MissingEncryptionKey,
	#[error("packed write error: {source}")]
	PacketWriteError {
		#[from]
		source: PacketWriteError,
	},
	#[error("encryption error: {source}")]
	EncryptionError {
		#[from]
		source: EncryptionError,
	},
	#[error("unknown")]
	Unknown,
}
