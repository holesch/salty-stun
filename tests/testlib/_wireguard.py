import enum
import hashlib
import struct
import time

import scapy.all as scapy
import scapy.contrib.wireguard as scapy_wg

from . import _crypto as crypto


class InjectedWireguardHandshakeErrors(enum.Enum):
    TOO_SHORT = enum.auto()
    TOO_LONG = enum.auto()
    MAC1_ERROR = enum.auto()
    EPHEMERAL_NULL = enum.auto()
    STATIC_NULL = enum.auto()
    STATIC_ENCRYPTED_NULL = enum.auto()
    TIMESTAMP_ENCRYPTED_NULL = enum.auto()


class InjectedWireguardTransportErrors(enum.Enum):
    INVALID_INDEX = enum.auto()
    PACKET_NULL = enum.auto()


class WireGuardSession:
    def __init__(self, remote_public_key, socket):
        self._static_key = dh_generate()
        self._remote_public_key = remote_public_key
        self._socket = socket
        self._my_index = 89
        self._chaining_key = None
        self._hash = None
        self._ephemeral = None
        self._remote_index = None

    def send_handshake(self, error=None):
        # Ci := Hash(Construction)
        construction = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
        self._hash = Hash(construction)
        initial_chaining_key = bytes(self._hash)

        # Hi := Hash(Ci ‖ Identifier)
        idenfitier = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
        self._hash.mix(idenfitier)

        # Hi := Hash(Hi ‖ Spub r)
        self._hash.mix(self._remote_public_key.public_bytes_raw())

        # (Epriv i, Epub i) := DH-Generate()
        self._ephemeral = dh_generate()

        # Ci := Kdf1(Ci, Epub i)
        self._chaining_key = kdf(
            1,
            initial_chaining_key,
            bytes(self._ephemeral.public_key().public_bytes_raw()),
        )[0]

        # msg.ephemeral := Epub i
        msg_ephemeral = self._ephemeral.public_key().public_bytes_raw()
        if error == InjectedWireguardHandshakeErrors.EPHEMERAL_NULL:
            msg_ephemeral = b"\x00" * len(msg_ephemeral)

        # Hi := Hash(Hi ‖ msg.ephemeral)
        self._hash.mix(msg_ephemeral)

        # (Ci, κ) := Kdf2(Ci, DH(Epriv i, Spub r))
        self._chaining_key, encryption_key = kdf(
            2, self._chaining_key, self._ephemeral.exchange(self._remote_public_key)
        )

        # msg.static := Aead(κ, 0, Spub i, Hi)
        static_public = self._static_key.public_key().public_bytes_raw()
        if error == InjectedWireguardHandshakeErrors.STATIC_NULL:
            static_public = b"\x00" * len(static_public)
        msg_static = aead_encrypt(encryption_key, 0, static_public, bytes(self._hash))
        if error == InjectedWireguardHandshakeErrors.STATIC_ENCRYPTED_NULL:
            msg_static = b"\x00" * len(msg_static)

        # Hi := Hash(Hi ‖ msg.static)
        self._hash.mix(msg_static)

        # (Ci, κ) := Kdf2(Ci, DH(Spriv i, Spub r))
        self._chaining_key, encryption_key = kdf(
            2, self._chaining_key, self._static_key.exchange(self._remote_public_key)
        )

        # msg.timestamp := Aead(κ, 0, Timestamp(), Hi)
        msg_timestamp = aead_encrypt(encryption_key, 0, timestamp(), bytes(self._hash))
        if error == InjectedWireguardHandshakeErrors.TIMESTAMP_ENCRYPTED_NULL:
            msg_timestamp = b"\x00" * len(msg_timestamp)

        # Hi := Hash(Hi ‖ msg.timestamp)
        self._hash.mix(msg_timestamp)

        request = scapy_wg.Wireguard(
            message_type="initiate"
        ) / scapy_wg.WireguardInitiation(
            sender_index=self._my_index,
            unencrypted_ephemeral=msg_ephemeral,
            encrypted_static=msg_static,
            encrypted_timestamp=msg_timestamp,
        )

        mac1 = calculate_mac1(request, self._remote_public_key)
        if error == InjectedWireguardHandshakeErrors.MAC1_ERROR:
            mac1 = mac1[:-1] + bytes([mac1[-1] ^ 0x01])
        request.mac1 = mac1

        to_send = bytes(request)

        if error == InjectedWireguardHandshakeErrors.TOO_SHORT:
            to_send = to_send[:-1]
        elif error == InjectedWireguardHandshakeErrors.TOO_LONG:
            to_send = to_send + b"\x00"

        self._socket.send(to_send)

    def __enter__(self):
        self.send_handshake()

        data = self._socket.recv(4096)
        response = scapy_wg.Wireguard(data)
        assert response.layers() == [scapy_wg.Wireguard, scapy_wg.WireguardResponse]

        assert response.mac1 == calculate_mac1(response, self._static_key.public_key())
        assert response.mac2 == b"\x00" * 16

        assert response.receiver_index == self._my_index

        # msg.ephemeral := Epub r
        ephemeral_responder = crypto.X25519PublicKey.from_public_bytes(
            response.unencrypted_ephemeral
        )

        # Cr := Kdf1(Cr , Epub r)
        self._chaining_key = kdf(
            1, self._chaining_key, ephemeral_responder.public_bytes_raw()
        )[0]

        # Hr := Hash(Hr ‖ msg.ephemeral)
        self._hash.mix(ephemeral_responder.public_bytes_raw())

        # Cr := Kdf1(Cr , DH(Epriv r, Epub i))
        # here: Cr := Kdf1(Cr , DH(Epriv i, Epub r))
        self._chaining_key = kdf(
            1, self._chaining_key, self._ephemeral.exchange(ephemeral_responder)
        )[0]

        # Cr := Kdf1(Cr , DH(Epriv r, Spub i))
        # here: Cr := Kdf1(Cr , DH(Spriv i, Epub r))
        self._chaining_key = kdf(
            1, self._chaining_key, self._static_key.exchange(ephemeral_responder)
        )[0]

        # (Cr , τ, κ) := Kdf3(Cr , Q)
        pre_shared_key = b"\x00" * 32
        self._chaining_key, hash_input, encryption_key = kdf(
            3, self._chaining_key, pre_shared_key
        )

        # Hr := Hash(Hr ‖ τ)
        self._hash.mix(hash_input)

        # msg.empty := Aead(κ, 0, ϵ, Hr )
        msg_empty = aead_decrypt(
            encryption_key, 0, response.encrypted_nothing, bytes(self._hash)
        )
        assert msg_empty == b""

        # Hr := Hash(Hr ‖ msg.empty)
        self._hash.mix(response.encrypted_nothing)

        # msg.sender := Ir
        self._remote_index = response.sender_index

        # (T send i = T recv r , T recv i = T send r) := Kdf2(Ci = Cr , ϵ)
        self._send_key, self._recv_key = kdf(2, self._chaining_key, b"")

        # N send i = N recv r = N recv i = N send r := 0
        self._send_counter = 0
        self._recv_counter = 0

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def send(self, data, error=None):
        # msg.receiver := Im'
        msg_receiver = self._remote_index
        if error == InjectedWireguardTransportErrors.INVALID_INDEX:
            msg_receiver ^= 0x01

        # pad packet to multiple of 16 bytes
        # P := P ‖0^16·⎡‖P‖/16⎤-‖P‖
        padding = b"\x00" * ((16 - (len(data) % 16)) % 16)
        data = bytes(data) + padding

        # msg.counter := N send m
        msg_counter = self._send_counter

        # msg.packet := Aead(T send m , N send m , P, ϵ)
        msg_packet = aead_encrypt(self._send_key, msg_counter, data, b"")
        if error == InjectedWireguardTransportErrors.PACKET_NULL:
            msg_packet = b"\x00" * len(msg_packet)

        # N send m := N send m + 1
        if error is None:
            self._send_counter += 1

        request = scapy_wg.Wireguard(
            message_type="transport"
        ) / scapy_wg.WireguardTransport(
            receiver_index=msg_receiver,
            counter=msg_counter,
            encrypted_encapsulated_packet=msg_packet,
        )

        self._socket.send(bytes(request))

    def request(self, data):
        self.send(data)

        data = self._socket.recv(4096)
        response = scapy_wg.Wireguard(data)
        assert response.layers() == [scapy_wg.Wireguard, scapy_wg.WireguardTransport]

        # msg.receiver := Im'
        assert response.receiver_index == self._my_index

        # msg.counter := N send m
        assert response.counter == self._recv_counter

        # msg.packet := Aead(T send m , N send m , P, ϵ)
        decrypted = aead_decrypt(
            self._recv_key,
            response.counter,
            response.encrypted_encapsulated_packet,
            b"",
        )

        # N send m := N send m + 1
        self._recv_counter += 1

        # check padding
        assert len(decrypted) % 16 == 0

        if not decrypted:
            # keep-alive packet
            return None

        padded_pkt = scapy.IP(decrypted)

        return scapy.IP(decrypted[: padded_pkt[scapy.IP].len])

    @property
    def private_key(self):
        return self._static_key


class Hash:
    def __init__(self, data):
        self._hash = hashlib.blake2s(data, digest_size=32).digest()

    def __bytes__(self):
        return self._hash

    def mix(self, data):
        h = hashlib.blake2s(self._hash, digest_size=32)
        h.update(data)
        self._hash = h.digest()


def kdf(n, key, input_):
    hash_ = crypto.BLAKE2s(32)
    hkdf = crypto.HKDF(
        algorithm=hash_, salt=key, length=hash_.digest_size * n, info=b""
    )
    output = hkdf.derive(input_)
    return [output[i : i + 32] for i in range(0, len(output), 32)]


# Aead(key, counter, plain text, auth text) ChaCha20Poly1305 AEAD, as specified
# in RFC7539 [17], with its nonce being composed of 32 bits of zeros followed
# by the 64-bit little-endian value of counter.
def aead_encrypt(key, counter, plaintext, auth_text):
    nonce = struct.pack("<xxxxQ", counter)
    return crypto.ChaCha20Poly1305(key).encrypt(nonce, plaintext, auth_text)


def aead_decrypt(key, counter, ciphertext, auth_text):
    nonce = struct.pack("<xxxxQ", counter)
    return crypto.ChaCha20Poly1305(key).decrypt(nonce, ciphertext, auth_text)


def dh_generate():
    return crypto.X25519PrivateKey.generate()


def timestamp():
    # TAI time has an offset of 10 seconds compared to UTC (as of 1970)
    tai_seconds = int(time.time()) + 10
    nanoseconds = int(time.time_ns() % 1_000_000_000)

    # TAI64N consists of 8 bytes for seconds and 4 bytes for nanoseconds
    tai64n = struct.pack(">QI", tai_seconds, nanoseconds)
    return tai64n


def calculate_mac1(msg, remote_public_key):
    label_mac1 = b"mac1----"
    h = hashlib.blake2s(label_mac1, digest_size=32)
    h.update(remote_public_key.public_bytes_raw())
    mac1_key = h.digest()
    return hashlib.blake2s(bytes(msg)[:-32], key=mac1_key, digest_size=16).digest()
