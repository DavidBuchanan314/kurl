from typing import Literal

import socket

"""
sudo modprobe tls
^^^ important!!!
"""

# linux/tls.h
TLS_TX = 1
TLS_RX = 2

TLS_1_3_VERSION = 0x0304
TLS_CIPHER_AES_GCM_128 = 51
TLS_CIPHER_CHACHA20_POLY1305 = 54

TLS_SET_RECORD_TYPE = 1
TLS_GET_RECORD_TYPE = 2

#linux/socket.h
SOL_TLS = 282

def make_crypto_info(iv: bytes, key: bytes, salt: bytes, rec_seq: int):
	buf = b""
	buf += (TLS_1_3_VERSION).to_bytes(2, "little")
	buf += (TLS_CIPHER_AES_GCM_128).to_bytes(2, "little")
	buf += iv # 8 bytes (TODO: does this need padding???) (no it doesn't)
	buf += key # 16 bytes
	buf += salt # 4
	buf += rec_seq.to_bytes(8, "little") # I think this is LE?
	return buf

def socket_set_key(s: socket.socket, direction: int, key: bytes, iv: bytes):
	# direction is either TLS_TX or TLS_RX
	s.setsockopt(SOL_TLS, direction, make_crypto_info(
		iv=iv[4:],
		key=key,
		salt=iv[:4],
		rec_seq=0
	))
