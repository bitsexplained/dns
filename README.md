# dns
[![Rust](https://github.com/bitsexplained/dns/actions/workflows/rust.yml/badge.svg)](https://github.com/bitsexplained/dns/actions/workflows/rust.yml)


# Simple DNS resolver in Rust
This repository contains a simple DNS resolver written in Rust. It listens on port 2053 (standard DNS port) and forwards queries to a recursive resolver.

# Prerequisites
  1. Rust (stable version recommended) - (```rustc```)
  2. Cargo package manager - (```cargo```)

# Installation
  1. Clone this repository: ```git clone https://github.com/bitsexplained/dns.git```
  2. Navigate to the repository directory: ```cd dns```
  3. Install dependencies: ```cargo build```

# Additional notes:
1. The server listens on port 2053 by default for incoming DNS queries.
2. The server performs recursive lookups to resolve the hostname.
3. The code uses the ```dns``` crate for parsing and generating DNS packets.
4. The ```utils``` crate provides some utility functions used by the server.
5. The ```buffer``` crate provides a buffer abstraction for handling byte data.


# Further development:
1. The server can be extended to support additional DNS record types.
2. The server can be configured to use specific DNS servers for lookups.
3. You can add logging and monitoring capabilities to the server.

# Disclaimer:

This is a basic DNS server implementation and may not be suitable for production use. It is intended for educational purposes and learning about DNS server implementation in Rust.
