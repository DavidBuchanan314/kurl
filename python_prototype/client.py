from scapy.layers.tls.all import *
import scapy.layers.tls.handshake
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, derive_private_key, SECP256R1
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Tuple
import socket
import hashlib

from key_derivation import *
import ktls

def c_dump(data):
	return ",".join(f"0x{n:02x}" for n in data)

class TLSClient:
	"""
	XXX: This is NOT A SECURE IMPLEMENTATION

	DO NOT USE IT FOR ANYTHING EXCEPT BREAKING THINGS
	"""

	def __init__(self, sock: socket.socket, hostname: str):
		self.s = sock
		self.hostname = hostname

		self.transcript = hashlib.sha256()

		self.client_hello()

		rtype, _, record = self.recv_record()
		assert(rtype == 22) # XXX: assume no fragmentation

		self.transcript.update(record)
		server_hello = TLS13ServerHello(record)
		server_hello.show()

		server_keyshare: TLS_Ext_KeyShare_SH = next(x for x in server_hello.ext if type(x) is TLS_Ext_KeyShare_SH)
		server_dh_pub = server_keyshare.server_share.pubkey
		dh_secret = self.keyshare.privkey.exchange(ECDH(), server_dh_pub)
		print("server keyshare:", server_keyshare.server_share.key_exchange.hex())
		print("dh secret:", dh_secret.hex())

		# by setting our privkey to 1, we turned ECDH into a nop
		assert(server_keyshare.server_share.key_exchange[1:32+1] == dh_secret)


		H0 = bytes(self.transcript.digest_size)
		early_secret = hkdf_extract(H0, H0)
		print("early secret", early_secret.hex()) # this is constant!!!

		derived_secret = hkdf_expand_label(early_secret, b"derived", hashlib.sha256(b"").digest(), 32)
		
		# bleh I can't get it to work... hardcoding from https://crypto.stackexchange.com/a/68668
		#derived_secret = bytes.fromhex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
		# ah, fixed it now... (hkdf_expand_label was broken)
		print("derived secret:", derived_secret.hex()) # also constant!

		handshake_secret = hkdf_extract(derived_secret, dh_secret)
		print("handshake secret:", handshake_secret.hex())

		client_handshake_traffic_secret = hkdf_expand_label(handshake_secret, b"c hs traffic", self.transcript.digest(), 32)
		print("client_handshake_traffic_secret:", client_handshake_traffic_secret.hex())
		server_handshake_traffic_secret = hkdf_expand_label(handshake_secret, b"s hs traffic", self.transcript.digest(), 32)
		print("server_handshake_traffic_secret:", server_handshake_traffic_secret.hex())
		# openssl key logging says we're correct at least up to here!!!

		server_handshake_key = hkdf_expand_label(server_handshake_traffic_secret, b"key", b"", 16)
		server_handshake_iv = hkdf_expand_label(server_handshake_traffic_secret, b"iv", b"", 12)
		print("server_handshake_key:", server_handshake_key.hex())
		print("server_handshake_iv:", server_handshake_iv.hex())
		server_handshake_cipher = AESGCM(server_handshake_key)

		client_handshake_key = hkdf_expand_label(client_handshake_traffic_secret, b"key", b"", 16)
		client_handshake_iv = hkdf_expand_label(client_handshake_traffic_secret, b"iv", b"", 12)
		print("client_handshake_key:", client_handshake_key.hex())
		print("client_handshake_iv:", client_handshake_iv.hex())
		client_handshake_cipher = AESGCM(client_handshake_key)

		i = 0
		while True:
			rtype, header_bytes, record = self.recv_record()
			print(rtype, record[:32])
			if rtype != 23:
				continue
			this_iv = (int.from_bytes(server_handshake_iv) ^ i).to_bytes(12)
			pt = server_handshake_cipher.decrypt(this_iv, record, header_bytes)
			assert(pt[-1] == 22)
			i += 1
			self.transcript.update(pt[:-1])
			cls = scapy.layers.tls.handshake._tls13_handshake_cls.get(pt[0], Raw)
			if cls is TLSFinished:
				print(pt) # can't parse...
				break
			else:
				print(repr(cls(pt[:-1], tls_session=server_hello.tls_session)))

		master_secret = hkdf_extract(hkdf_expand_label(handshake_secret, b"derived", hashlib.sha256(b"").digest(), 32), H0)
		print("master_secret:", master_secret.hex())
		
		client_application_traffic_secret_0 = hkdf_expand_label(master_secret, b"c ap traffic", self.transcript.digest(), 32)
		server_application_traffic_secret_0 = hkdf_expand_label(master_secret, b"s ap traffic", self.transcript.digest(), 32)
		print("client_application_traffic_secret_0:", client_application_traffic_secret_0.hex())
		print("server_application_traffic_secret_0:", server_application_traffic_secret_0.hex())

		client_application_key = hkdf_expand_label(client_application_traffic_secret_0, b"key", b"", 16)
		client_application_iv = hkdf_expand_label(client_application_traffic_secret_0, b"iv", b"", 12)
		#client_application_cipher = AESGCM(client_application_key)
		server_application_key = hkdf_expand_label(server_application_traffic_secret_0, b"key", b"", 16)
		server_application_iv = hkdf_expand_label(server_application_traffic_secret_0, b"iv", b"", 12)

		finished_key = hkdf_expand_label(client_handshake_traffic_secret, b"finished", b"", 32)
		verify_data = hmac_digest(finished_key, self.transcript.digest())


		"""
		s.setsockopt(linux_ktls.SOL_TLS, linux_ktls.TLS_TX, linux_ktls.make_crypto_info(
			iv=client_handshake_iv[4:],
			key=client_handshake_key,
			salt=client_handshake_iv[:4],
			rec_seq=0)
		)
		s.sendmsg([bytes(TLSFinished(vdata=verify_data))], [(linux_ktls.SOL_TLS, linux_ktls.TLS_SET_RECORD_TYPE, (22).to_bytes())])
		"""
		
		msg = bytes(TLS13(
			type=23,
			inner=client_handshake_cipher.encrypt(
				client_handshake_iv,
				bytes(TLSFinished(vdata=verify_data)) + bytes([22]),
				bytes.fromhex("1703030035")  # always same (for our usecase...)
			)
		))
		print(msg.hex())
		s.sendall(msg) # handshake complete!!!!

		# testing doing the encryption manually instead of via kernel (it's almost easier...)
		"""
		msg = bytes(TLS13(
			type=23,
			inner=client_application_cipher.encrypt(
				client_application_iv,
				b"hello\n" + bytes([23]),
				bytes.fromhex("1703030017")  # always same (for our usecase...)
			)
		))
		print(msg.hex())
		s.sendall(msg)
		"""

		s.setsockopt(socket.SOL_TCP, socket.TCP_ULP, b"tls")
		ktls.socket_set_key(s, ktls.TLS_TX, client_application_key, client_application_iv)
		ktls.socket_set_key(s, ktls.TLS_RX, server_application_key, server_application_iv)

		s.sendall(b"GET /stuff/ HTTP/1.1\r\nHost: retr0.id\r\nConnection: close\r\n\r\n")

		# this is messy (and overengineered) because we need to filter out non-application records.
		# there's definitely room for simplification.
		while True:
			msg, cmsgs, flags, _ = s.recvmsg(0x4000, socket.CMSG_SPACE(1))
			if len(cmsgs) != 1:
				print(msg, cmsgs, flags)
				break
			cmsg_level, cmsg_type, cmsg_data = cmsgs[0]
			if cmsg_level != ktls.SOL_TLS:
				continue
			if cmsg_type != ktls.TLS_GET_RECORD_TYPE:
				continue
			record_type = cmsg_data[0]
			if record_type != 23:
				print(msg)
				continue
			print(msg.decode())
	
	def recv_record(self) -> Tuple[int, bytes]:
		# XXX: ignores fragmentation!
		header_bytes = self.s.recv(5)
		content_type, legacy_version, length = struct.unpack(">BHH", header_bytes)
		assert(legacy_version == 0x0303)
		fragment = b""
		while len(fragment) < length:
			tmp = self.s.recv(length - len(fragment))
			if not tmp:
				break
			fragment += tmp
		assert(len(fragment) == length)
		return content_type, header_bytes, fragment

	def client_hello(self):
		self.keyshare = KeyShareEntry() # defaults to secp256r1
		self.keyshare.privkey = derive_private_key(1, SECP256R1()) # set a weak key!!!
		self.keyshare.key_exchange = self.keyshare.privkey.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
		print("client key share:", self.keyshare.key_exchange.hex())
		hello = TLS13ClientHello(
			random_bytes=b"A"*32,
			ciphers=[TLS_AES_128_GCM_SHA256],
			ext=[
				TLS_Ext_SupportedVersion_CH(
					versions=[0x0304] # tls1.3
				),
				TLS_Ext_SupportedGroups(
					groups=[23] #secp256r1
				),
				# we're never going to verify signatures anyway, so advertise for broad compat (TODO: widen!)
				TLS_Ext_SignatureAlgorithms(
					sig_algs=[
						0x0401, # rsa_pkcs1_sha256
						0x0403, # ecdsa_secp256r1_sha256
						0x0804, # rsa_pss_rsae_sha256
					]
				),
				TLS_Ext_KeyShare_CH(
					client_shares=[self.keyshare]
				),

				# theory: putting this last will make it easier to build dynamically
				TLS_Ext_ServerName(
					servernames=[
						ServerName(servername=self.hostname)
					]
				),
			]
		)
		record = TLS13(
			type=22,
			inner=hello
		)
		assert(bytes(record) == bytes(record)) # check serialisation is consistent... (random_bytes must be set, apparently)
		foo = bytes(record)
		print(f"static const unsigned char CLIENT_HELLO[] = {{{c_dump(foo)}}};")
		TLS13(foo).show()
		self.transcript.update(foo[5:])
		self.s.sendall(foo)

if __name__ == "__main__":
	hostname = "retr0.id"
	port = 443
	hostname = "localhost"
	port = 1337

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((hostname, port))
	client = TLSClient(s, hostname)
