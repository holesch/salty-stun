salty-stun(1)

# NAME

salty-stun - STUN server for WireGuard®

# SYNOPSIS

*salty-stun* [_options_]

# DESCRIPTION

*salty-stun* is a STUN server that runs inside a WireGuard tunnel. It listens
for incoming STUN requests and responds with the transport address of the
WireGuard endpoint. This allows two peers to establish a P2P VPN tunnel through
NATs.

# OPTIONS

*-h*
	Show help message and exit.

*-V*
	Show version information and exit.

*-p* _port_
	Listen on UDP port _port_. The default port is 51820 or 3478 if running in
	plain STUN mode (see *-P*).

*-k* _key_file_
	Read the private key from _key_file_. The key must be encoded in base64. By
	default, the key is read from /etc/salty-stun/private-key.

*-K* _key_log_
	Write keys to _key_log_, which can be used to decrypt WireGuard traffic with
	Wireshark. By default, keys are not logged.

*-l* _level_
	Set the log level to _level_. Valid values are one of _error_, _warning_,
	_info_ or _debug_. The default log level is _info_.

*-n* _max_sessions_
	Set the maximum number of concurrent sessions to _max_sessions_ (default
	1024).

*-f* _fd_
	Accept incoming connections on file descriptor _fd_ instead of creating a
	new socket.

*-P*
	Run in plain STUN mode: do not use WireGuard for transport. This is useful
	when you want to use *salty-stun* as a regular STUN server.

# EXAMPLE

Generate a private key:

```
$ wg genkey > ./private-key
```

Start the STUN server:

```
$ salty-stun -k ./private-key
```

Create a WireGuard configuration file:

```
$ cat << EOF > ./wg0.conf
[Interface]
PrivateKey = $(wg genkey)

[Peer]
PublicKey = $(wg pubkey < ./private-key)
Endpoint = 127.0.0.1:51820
AllowedIPs = 100.64.0.4/32
EOF
```

Bring up the WireGuard interface:

```
# ip link add dev wg0 type wireguard
# wg setconf wg0 ./wg0.conf
# ip addr add dev wg0 100.64.0.5/24
# ip link set dev wg0 up
```

Get the reflexive transport address of the WireGuard endpoint with
_turnutils_(1):

```
$ turnutils_stunclient 100.64.0.4
```

# NOTES

WireGuard is a registered trademark of Jason A. Donenfeld. This project is not
affiliated with or endorsed by WireGuard or its developers.

# AUTHORS

Maintained by Simon Holesch <simon@holesch.de>. Sources can be found at
https://github.com/holesch/salty-stun

# SEE ALSO

_wg_(8)
