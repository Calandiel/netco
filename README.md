# netco
A low level UDP networking library for real-time applications and games. Largely inspired by [Gaffer on Games][gog]. Developed as an alternative to [ENet][enet], [laminar][laminar] and [naia][naia].

[enet]: http://enet.bespin.org/
[laminar]: https://github.com/TimonPost/laminar
[naia]: https://github.com/naia-lib/naia
[gog]: https://gafferongames.com/

Core features are implemented and have been tested in an in-development project. The library is under development but not very likely to have significant API changes. It'll land on crates.io when the accompanying documentation is finished and when library itself is thoroughly unit-tested.


## Features

* [x] Unreliable packets
* [x] Reliable ordered packets
* [x] Encrypted packets
* [x] Protocol version monitoring
* [x] Connection management
* [x] Account creation and management
* [x] Timeout detection
* [x] Basic DoS mitigation
* [x] Protocol versioning
* [x] Handshake protocol
* [x] Multithreadable

### Planned

* [ ] Fragmentable packets
* [ ] Congestion control
* [ ] Publish the library to crates.io
* [ ] Unit tests


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
).unwrap();

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



