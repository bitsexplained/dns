# dns
[![Rust](https://github.com/bitsexplained/dns/actions/workflows/rust.yml/badge.svg)](https://github.com/bitsexplained/dns/actions/workflows/rust.yml)


# Simple DNS resolver in Rust
This repository contains a simple DNS resolver written in Rust.
# Prerequisites
  1. Rust (stable version recommended) - (```rustc```)
  2. Cargo package manager - (```cargo```)

# Run
  1. Clone this repository: ```git clone https://github.com/bitsexplained/dns.git```
  2. Navigate to the repository directory: ```cd dns```
  3. Run the server: ```cargo run```
  4. We will use the ```dig``` command to gather dns info
     - run the following command on another terminal window ```dig @127.0.0.1 -p 2053 www.google.com```
     - The following screeshot shows well formatted dns information
     <img width="760" alt="Screenshot 2024-01-09 at 18 20 14" src="https://github.com/bitsexplained/dns/assets/28337458/533d35eb-be83-4e67-a6c1-1409a004b7b4">

# Additional notes:
1. The server listens on port 2053 by default for incoming DNS queries.
2. The server performs recursive lookups to resolve the hostname.
3. The code uses the ```dns``` crate for parsing and generating DNS packets.
4. The ```utils``` crate provides some utility functions used by the server.
5. The ```buffer``` crate provides a buffer abstraction for handling byte data.
     


# Further development:
1. Package the codebase and publish as a crate on crates.io(Currently ongoing)
2. Expand the server's capabilities to accommodate additional DNS record types.
3. The server can be configured to use specific DNS servers for lookups.
4. Introduce logging and monitoring functionalities for enhanced observability and troubleshooting.


# Disclaimer:

This is a basic DNS server implementation and may not be suitable for production use. It is intended for educational purposes and learning about DNS server implementation in Rust.
