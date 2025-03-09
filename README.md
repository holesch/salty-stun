# salty-stun

[![on-push](https://github.com/holesch/salty-stun/actions/workflows/on-push.yml/badge.svg)](https://github.com/holesch/salty-stun/actions/workflows/on-push.yml)

salty-stun is a STUN server that runs inside a [WireGuard®][wireguard] tunnel.
It listens for incoming STUN requests and responds with the transport address of
the WireGuard endpoint. This allows two peers to establish a P2P VPN tunnel
through NATs.

[wireguard]: https://www.wireguard.com/

## Installation

salty-stun uses [libsodium] and [libb2] for cryptographic operations. On a
debian-based system, you can install these dependencies with:

```console
$ sudo apt install libsodium-dev libb2-dev
```

[libsodium]: https://doc.libsodium.org/
[libb2]: https://blake2.net

To build and install salty-stun, run the following commands:

```console
$ meson setup build
$ meson compile -C build
$ sudo meson install -C build
```

## Usage

See the man page [salty-stun(1)](./salty-stun.1.scd) for usage information.

## Acknowledgements

The idea is based on a blog post by Rytis Karpuška at NordVPN: [Reaching Beyond
1Gbps: How we achieved NAT traversal with vanilla WireGuard][1].

WireGuard is a registered trademark of Jason A. Donenfeld. This project is not
affiliated with or endorsed by WireGuard or its developers.

[1]: https://nordsecurity.com/blog/reaching-beyond-1gbps
