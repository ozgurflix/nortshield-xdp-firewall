Note: Since I had difficulty finding an XDP-based game firewall on the internet, I developed this firewall project. It still needs improvement, such as blocking DNS and similar attacks, as well as adding features like A2S Caching.
# XDP Game Firewall

NortShield Game Firewall is a high-performance firewall application designed to protect game servers. This project uses Linux's eXtensible Data Path (XDP) technology to manage network traffic and protect against various attacks.



## Features

- **Rate Limiting**: Rate limiting for UDP, TCP, SYN, and ICMP traffic.
- **Log Management**: Comprehensive log management system for recording and monitoring events.
- **Rule Management**: Management of protection rules for game servers.
- **Filtering**: Traffic filtering based on specific game protocols.

## Requirements

- Linux operating system (Ubuntu 20.04 recommended)
- XDP-compatible network card
- Required libraries (like libbpf)

## Installation

1. Clone the project:

   git clone https://github.com/ozgurflix/nortshield-xdp-firewall.git
   cd nortshield-xdp-firewall

2. Install required libraries:

   sudo apt-get install libbpf-dev clang llvm

3. Build the application:

   make
## Usage

1. Start the application:

   sudo ./xdp_firewall

2. Edit the necessary configuration files (e.g., `rules.json`, `filters.json`).

3. Check the `logs.json` file to monitor logs.
