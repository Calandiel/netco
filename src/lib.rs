#![deny(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

pub mod account;
pub mod client;
pub mod connection;
pub mod cryptography;
pub mod error;
pub mod packet;
pub mod server;
pub mod socket;

const MAX_PACKET_SIZE: usize = 1000;

pub fn sequence_greater_than(s1: u16, s2: u16) -> bool {
	((s1 > s2) && (s1.wrapping_sub(s2) <= 32768)) || ((s1 < s2) && (s2.wrapping_sub(s1) > 32768))
}
