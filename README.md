# Status notice
This repo is largely very old code I've wrote over half a decade ago while learning the Rust language, with very little maintanance done over the years.
Needless to say, while the code works (I've integrated it in many projects), you probably don't want to look under the hood.
If you need a similar library, I suggest searching for a crate here:
https://arewegameyet.rs/ecosystem/networking/

# netco
A low level UDP networking library for real-time applications and games. Developed as an alternative to [ENet][enet], [laminar][laminar] and [naia][naia]. Partially inspired by [Gaffer on Games][gog].

[enet]: http://enet.bespin.org/
[laminar]: https://github.com/TimonPost/laminar
[naia]: https://github.com/naia-lib/naia
[gog]: https://gafferongames.com/

Core features are implemented and have been tested in an in-development project. The library is under development but not very likely to have significant API changes. It'll land on crates.io when the accompanying documentation is finished and when library itself is thoroughly unit-tested.


## Table of contents:
- [Design and library comparison](#design-and-library-comparison)
- [Features](#features)
- [Getting Started](#getting-started)
- [Contributing](#contribution)
- [Authors](#authors)
- [License](#license)


## Design and library comparison
`netco` aims to be a low level alternative to networking libraries for games and other real-time applications that require reliability and connections.
The API aims to be simple and based around function calls. All packet sending is handled through functions that take in a vector and `netco` handles their reliability, verification and encryption, as applicable.

Compared to `ENet` and `laminar`, it provides some common abstractions that most games utilizing the authoritative server-client architecture implement (for example, Clients/Peers are referenced by Strings representing their nicknames, instead of raw addresses).
`netco` also provides password based verification for connections, both at a server level and at an account level, which offers additional protection against malicious actors that `ENet` can't offer (as it needs to accept a connection before it can be verified with a password at an application level).

Unlike `laminar`, it takes a much stronger stance on heartbeats and reliability. *All* reliable packets in `netco` are guaranteed to be delivered, whereas in laminar, [reliability breaks when the ring buffer overflows][lambug], a conscious design decision taken by `laminar`'s developers.

[lambug]: https://github.com/TimonPost/laminar/issues/303

`netco` should *never* panic and contains no unsafe code. This was verified by extensive use in one of authors projects but more formal unit testing will be performed before the library is published to crates.io.

## Getting Started

Add netco package to your `Cargo.toml` file.

```toml
[dependencies]
netco = { git = "https://github.com/Calandiel/netco.git" }
```


Create the server and the client

```rust
// SERVER
let mut sr = netco::server::Server::new(
  "127.0.0.1:3456", // address to bind
  "password".to_string(), // server password that clients need to provide to connect
  100, // Game version
  1000 // Maximum number of players
).unwrap(); // In a real application you'd likely want to deal with any potential errors instead of panicking when they occur

// CLIENT
let mut cl = netco::client::Client::new(
  "127.0.0.1:4567", // address to bind
  "127.0.0.1:3456", // server address
  100, // Game version
  "password".to_string(), // server password that clients need to provide to connect
  "Nickname".to_string(), // Nickname of the account to use
  "client_password".to_string(), // Password of the account to use
  true,
).unwrap();
```


Call every game frame to send and receive packets

```rust
// SERVER
sr.service().unwrap();

// CLIENT
cl.service().unwrap();
```


Messages are stored after servicing until the application handles them

```rust
// SERVER
while let Some(v) = sr.get_next_message() { // get next message returns None when there are no more messages to handle
  println!("SERVER EVENT: {:?}", v);
  // the event is an enum and can contain information about received data packets, newly joining players, time-outs and so on
  // in a real application, you'd want to handle it here (akin to how one would handle events in ENet)
}

// CLIENT
while let Some(v) = cl.get_next_message() {
  println!("CLIENT EVENT: {:?}", v);
}
```


Sending data

```rust
// All packet sending functions take in a vector of bytes as inputs
// In a real application, you'd likely want to create this vector with some serialization library
// Bincode and serde are good candidates if one isn't very heavily bandwidth limited.
let data = vec![1, 2, 3, 4, 5];

// Unreliable packets:
// SERVER
sr.send_unreliable_unordered_packet(
  &"PlayerNickname".to_string(), // the server also needs to specify which client to send the data to. Clients are referenced by their nickname (netco exposes a higher level abstraction than ENet and laminar)
  data.clone()
);
// CLIENT
cl.send_unreliable_unordered_packet(data.clone());

// Reliable packets:
// SERVER
sr.send_reliable_ordered_packet(&"PlayerNickname".to_string(), data.clone());
// CLIENT
cl.send_reliable_ordered_packet(data.clone());

// Encrypted packets:
// SERVER
sr.send_encrypted_packet(&"PlayerNickname".to_string(), data.clone());
// CLIENT
cl.send_encrypted_packet(data.clone());


// Besides that, there's also a variety of functions to handle accounts themselves.
// For example, logged-in clients can update their passwords:
cl.change_password("NewPassword".to_string()).unwrap();
```


## Authors

- [Calandiel](https://github.com/Calandiel)
