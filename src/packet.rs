use num_derive::{FromPrimitive, ToPrimitive};

#[derive(FromPrimitive, ToPrimitive, Clone, Copy, Debug)]
pub enum ClientPacketTypes {
	//
	// Sends in client salt, includes protocol version.
	// Includes clients public key
	// Padded to 1k bytes
	Greeting,
	// Incudes encrypted hashed password and nickname as well as hashed server password -- padded to 1k bytes
	Login,
	Disconnect,
	ChangePassword,
	DeleteAccount,
	EncryptedPacket,
	UnreliableUnordered,
	ReliableOrdered,
	//
	Ping,
}

#[derive(FromPrimitive, ToPrimitive, Clone, Copy, Debug)]
pub enum ServerPacketTypes {
	//
	// Sends back server salt, server public key and a cryptographic nonce
	Greeting,
	BadProtocol,
	TooManyPlayers,
	//
	WrongServerPassword,
	WrongAccountPassword,
	AccountExists,
	AccountDoesNotExist,
	AccountInUse,
	LoginSuccess,
	//
	Kick,
	Ban,
	//
	Ping,
	//
	UnreliableUnordered,
	ReliableOrdered,
	EncryptedPacket,
}

// General data packet types:
// -- unreliable, unsequenced
// -- unreliable, sequenced
// -- reliable, unsequenced
// -- reliable, sequenced
// -- reliable, sequenced, encrypted
