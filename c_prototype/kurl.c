// make vscode shut up about headers...
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif // _DEFAULT_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include <linux/tls.h>

#include <string.h>

#include <assert.h>

//#define DEBUG 1

#ifdef DEBUG
#define DBG_ASSERT(x) assert(x)
#else
#define DBG_ASSERT(x) do { if (x) {} } while (0)
#endif

#define IP_ADDR "93.184.215.14"
#define PORT 443

/*
Useful reference: https://github.com/smuellerDD/libkcapi

https://github.com/nibrunie/af_alg-examples

General notes:
- There's a big lack of error handling!
- There are lots of fd leaks!
- These things are both fine because we're code golfing ;)

TODO: consider replacing send/recv with write/read, when flag is 0
*/

// this also contains the server name
static const unsigned char DNS_REQ[] = {0xa4,0xb5,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x62,0x69,0x6e,0x61,0x72,0x79,0x04,0x67,0x6f,0x6c,0x66,0x00,0x00,0x01,0x00,0x01};

// nb: this contains the server name
static const unsigned char CLIENT_HELLO[] = {0x16,0x03,0x03,0x00,0xa7,0x01,0x00,0x00,0xa3,0x03,0x03,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x00,0x00,0x02,0x13,0x01,0x01,0x00,0x00,0x78,0x00,0x2b,0x00,0x03,0x02,0x03,0x04,0x00,0x0a,0x00,0x04,0x00,0x02,0x00,0x17,0x00,0x0d,0x00,0x08,0x00,0x06,0x04,0x01,0x04,0x03,0x08,0x04,0x00,0x33,0x00,0x47,0x00,0x45,0x00,0x17,0x00,0x41,0x04,0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5,0x00,0x00,0x00,0x0e,0x00,0x0c,0x00,0x00,0x09,0x6c,0x6f,0x63,0x61,0x6c,0x68,0x6f,0x73,0x74};
// TODO: the "random" value in CLIENT_HELLO is currently just padding. we could slot the DERIVED_SECRET value in there to save space!
static const unsigned char DERIVED_SECRET[32] = {0x6f,0x26,0x15,0xa1,0x08,0xc7,0x02,0xc5,0x67,0x8f,0x54,0xfc,0x9d,0xba,0xb6,0x97,0x16,0xc0,0x76,0x18,0x9c,0x48,0x25,0x0c,0xeb,0xea,0xc3,0x57,0x6c,0x36,0x11,0xba};

// TODO: delet this (do it on-stack?) (finish data starts at offset 9)
static unsigned char CLIENT_FINISHED[] = {0x17,0x03,0x03,0x00,0x35, 0x14,0x00,0x00,0x20,    0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,   0x16, 0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41};

static unsigned char H0[32]; // 32 zeroes 

static unsigned char recvbuf[0x10100]; // enough for 16-bit length, plus headers
static unsigned char transcript_buf[0x10000]; // 64k ought to be enough for anyone!
static size_t transcript_len = 0;

static int algfd; //reusable? socket(AF_ALG, SOCK_SEQPACKET, 0);

// only here for debugging
static void hexdump(unsigned char *buf, size_t len)
{
	for (size_t i=0; i<len; i++) {
		printf("%02x", (unsigned char)buf[i]);
	}
}

static int alg_sock(const char *type, const char *name)
{
	algfd = socket(AF_ALG, SOCK_SEQPACKET, 0); // actually we need a new one each time????
	DBG_ASSERT(algfd >= 0);
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
	};
	strcpy((char*)sa.salg_type, type);
	strcpy((char*)sa.salg_name, name);
	DBG_ASSERT(bind(algfd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	int res = accept(algfd, NULL, 0);
	DBG_ASSERT(res >= 0);
	return res;
}

static void sha256(unsigned char res[32], unsigned char *buf, size_t len)
{	
	int sfd = alg_sock("hash", "sha256");
	DBG_ASSERT(send(sfd, buf, len, 0) == (ssize_t)len);
	DBG_ASSERT(recv(sfd, res, 32, 0) == 32);
	// XXX: leaks sfd
}

// aka hkdf_extract(salt, ikm)
static void hmac_sha256(unsigned char *res, unsigned char key[32], unsigned char *data, size_t len)
{
	int sfd = alg_sock("hash", "hmac(sha256)");
	setsockopt(algfd, SOL_ALG, ALG_SET_KEY, key, 32);
	DBG_ASSERT(send(sfd, data, len, 0) == (ssize_t)len);
	DBG_ASSERT(recv(sfd, res, 32, 0) == 32);
	// XXX: leaks sfd
}

// nb: will always fill 32 bytes of res (maybe)
static void hkdf_expand_label(unsigned char *res, unsigned char secret[32], char *label, unsigned char *ctx, size_t ctxlen, size_t len)
{
	// this is really gross and will need to be mostly rewritten when we ditch libc
	unsigned char buf[0x100] = {0, len, 6+strlen(label), 't', 'l', 's', '1', '3', ' '};
	size_t ptr = 2 + 1 + 6;
	strcpy((char*)buf+ptr, label);
	ptr += strlen(label);
	buf[ptr++] = ctxlen;
	memcpy(buf+ptr, ctx, ctxlen);
	ptr += ctxlen;
#ifdef DEBUG
	//printf("hkdf_expand_label buf (len=%lu): ", ptr);
	//hexdump(buf, ptr);
	//printf("\n");
#endif
	buf[ptr++] = 1; // hkdf_expand counter suffix
	hmac_sha256(res, secret, buf, ptr);
}

/* nb: this encrypts/decrypts "in place". length includes AD len, and tag len for decrypts */
static void aes_gcm(unsigned char *buf, int op, unsigned char key[16], unsigned char iv[12], size_t len, size_t adlen)
{
	int sfd = alg_sock("aead", "gcm(aes)");
	setsockopt(algfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 16);
	setsockopt(algfd, SOL_ALG, ALG_SET_KEY, key, 16);

	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(4) + CMSG_SPACE(4+12)] = {0};
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),

		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	struct cmsghdr *cmsg;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(uint32_t *)CMSG_DATA(cmsg) = op;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(uint32_t *)CMSG_DATA(cmsg) = adlen;

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(4+12);
	struct af_alg_iv *aiv = (void *)CMSG_DATA(cmsg);
	aiv->ivlen = 12;
	memcpy(aiv->iv, iv, 12);

	// TODO: finish this!!!
	DBG_ASSERT(sendmsg(sfd, &msg, 0) >= 0);
	ssize_t reslen = op == ALG_OP_ENCRYPT ? len + 16 : len - 16;
	DBG_ASSERT(recv(sfd, buf, reslen, 0) == reslen);
}

static uint32_t do_dns(void)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	DBG_ASSERT(s >= 0);
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr("127.0.0.53"),
		.sin_port = htons(53),
	};
	DBG_ASSERT(connect(s, (struct sockaddr*)&sin, sizeof(sin)) == 0);
	//DBG_ASSERT(sendto(s, DNS_REQ, sizeof(DNS_REQ), 0, (struct sockaddr*)&sin, sizeof(sin)) == sizof(DNS_REQ));
	DBG_ASSERT(send(s, DNS_REQ, sizeof(DNS_REQ), 0) == sizeof(DNS_REQ));
	DBG_ASSERT(recv(s, recvbuf, sizeof(recvbuf), 0) > 0);
	return *(uint32_t*)(recvbuf+41); // assuming the DNS server uses compression, the first ipv4 addr will be at the same place for a given query response
}

static int tcp_connect(void)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	DBG_ASSERT(s >= 0);
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = do_dns(),
		.sin_port = htons(PORT),
	};
	DBG_ASSERT(connect(s, (struct sockaddr*)&sin, sizeof(sin)) == 0);
	return s;
}

// receive the next record into recvbuf. does not account for record fragmentation.
// returns number of bytes of recvbuf populated (includes header)
static size_t recv_record(int s)
{
	ssize_t ptr = recv(s, recvbuf, 5, 0);
	DBG_ASSERT(ptr == 5);
	ssize_t msglen = (recvbuf[3]<<8) + recvbuf[4] + 5;
	while (ptr < msglen)
	{
		size_t readlen = recv(s, recvbuf+ptr, msglen - ptr, 0);
		DBG_ASSERT(readlen > 0); // XXX: will infinite loop on EOF!
		ptr += readlen;
	}
	assert(ptr == msglen);
	return ptr;
}

static void ktls_set_key(int s, int direction, unsigned char key[16], unsigned char iv[12])
{
	struct tls12_crypto_info_aes_gcm_128 crypto_info = {
		.info.version = TLS_1_3_VERSION,
		.info.cipher_type = TLS_CIPHER_AES_GCM_128,
		.rec_seq = {0}
	};
	memcpy(crypto_info.iv, iv+4, 8);
	memcpy(crypto_info.key, key, 16);
	memcpy(crypto_info.salt, iv, 4);
	DBG_ASSERT(setsockopt(s, SOL_TLS, direction, &crypto_info, sizeof(crypto_info)) == 0);
}

static void tls13_handshake(int s)
{
	//int transcript = alg_sock("hash", "sha256"); // will be updated incrementally
	unsigned char transcript_hash[32];
	unsigned char dh_secret[32];

	/* SEND CLIENT HELLO (and update transcript) */
	DBG_ASSERT(send(s, CLIENT_HELLO, sizeof(CLIENT_HELLO), 0) == sizeof(CLIENT_HELLO)); // TODO: make sure it all gets sent at once?
#ifdef DEBUG
	printf("client hello (len=%lu): ", sizeof(CLIENT_HELLO));
	hexdump((unsigned char*)CLIENT_HELLO, sizeof(CLIENT_HELLO));
	printf("\n");
#endif
	//DBG_ASSERT(send(transcript, CLIENT_HELLO+5, sizeof(CLIENT_HELLO)-5, MSG_MORE) == sizeof(CLIENT_HELLO)-5);
	memcpy(transcript_buf+transcript_len, CLIENT_HELLO+5, sizeof(CLIENT_HELLO)-5); // nb: we could skip this copy by overlapping the client hello and transcript buf
	transcript_len += sizeof(CLIENT_HELLO)-5;

	/* RECEIVE SERVER HELLO (and update transcript) */
	size_t server_hello_len = recv_record(s); // read the server hello into recvbuf
#ifdef DEBUG
	printf("server hello (len=%lu): ", server_hello_len);
	hexdump(recvbuf, server_hello_len);
	printf("\n");
#endif
	DBG_ASSERT(recvbuf[0] == 22); // is handshake msg
	DBG_ASSERT(recvbuf[5] == 2); // is server hello
	//DBG_ASSERT(send(transcript, recvbuf+5, server_hello_len-5, MSG_MORE) == (ssize_t)server_hello_len-5);
	memcpy(transcript_buf+transcript_len, recvbuf+5, server_hello_len-5); // nb: we could skip this copy by overlapping the client hello and transcript buf
	transcript_len += server_hello_len-5;

	/* grab the current transcript hash state */
	//DBG_ASSERT(recv(transcript, transcript_hash, sizeof(transcript_hash), MSG_MORE) == sizeof(transcript_hash));
	sha256(transcript_hash, transcript_buf, transcript_len);

#ifdef DEBUG
	printf("transcript hash (client_hello||server_hello): ");
	hexdump(transcript_hash, sizeof(transcript_hash));
	printf("\n");
#endif

	/* extract server's ecdh share from the server hello */
	size_t extension = 5 + 4 + 2 + 32 + 1 + 2 + 1 + 2; // the extensions start at a fixed offset
	// nb: we ignore the extensions length! we may read OOB.
	while (*(uint16_t*)(recvbuf+extension) != 0x3300) { // search for key_share
		extension += 2 + 2 + (recvbuf[extension+2]<<8) + recvbuf[extension+3]; // skip over an extension
	}
	memcpy(dh_secret, recvbuf+extension+9, 32); // extract dh_secret (nb, this might be an unnecessary copy!)
#ifdef DEBUG
	printf("dh_secret: ");
	hexdump(dh_secret, sizeof(dh_secret));
	printf("\n");
#endif

	/* derive handshake_secret */
	unsigned char handshake_secret[32];
	hmac_sha256(handshake_secret, (unsigned char*)DERIVED_SECRET, dh_secret, 32);
#ifdef DEBUG
	printf("handshake_secret: ");
	hexdump(handshake_secret, sizeof(handshake_secret));
	printf("\n");
#endif

	/* derive handshake encryption keys */
	unsigned char client_handshake_traffic_secret[32];
	unsigned char client_handshake_traffic_secret_key[32]; // nb: 16 byte really
	unsigned char client_handshake_traffic_secret_iv[32]; // nb: 12 byte really
	hkdf_expand_label(client_handshake_traffic_secret, handshake_secret, "c hs traffic", transcript_hash, 32, 32);
	hkdf_expand_label(client_handshake_traffic_secret_key, client_handshake_traffic_secret, "key", NULL, 0, 16);
	hkdf_expand_label(client_handshake_traffic_secret_iv, client_handshake_traffic_secret, "iv", NULL, 0, 12);
#ifdef DEBUG
	printf("client_handshake_traffic_secret: ");
	hexdump(client_handshake_traffic_secret, sizeof(client_handshake_traffic_secret));
	printf("\n");
	printf("client_handshake_traffic_secret_key: ");
	hexdump(client_handshake_traffic_secret_key, 16);
	printf("\n");
	printf("client_handshake_traffic_secret_iv: ");
	hexdump(client_handshake_traffic_secret_iv, 12);
	printf("\n");
#endif

	unsigned char server_handshake_traffic_secret[32];
	unsigned char server_handshake_traffic_secret_key[32]; // nb: 16 byte really
	unsigned char server_handshake_traffic_secret_iv[32]; // nb: 12 byte really
	hkdf_expand_label(server_handshake_traffic_secret, handshake_secret, "s hs traffic", transcript_hash, 32, 32);
	hkdf_expand_label(server_handshake_traffic_secret_key, server_handshake_traffic_secret, "key", NULL, 0, 16);
	hkdf_expand_label(server_handshake_traffic_secret_iv, server_handshake_traffic_secret, "iv", NULL, 0, 12);
#ifdef DEBUG
	printf("server_handshake_traffic_secret: ");
	hexdump(server_handshake_traffic_secret, sizeof(server_handshake_traffic_secret));
	printf("\n");
	printf("server_handshake_traffic_secret_key: ");
	hexdump(server_handshake_traffic_secret_key, 16);
	printf("\n");
	printf("server_handshake_traffic_secret_iv: ");
	hexdump(server_handshake_traffic_secret_iv, 12);
	printf("\n");
#endif

	/*
	loop through server handshake records, decrypt them, and add the plaintexts to
	the transcript buffer. break once the finish record is reached.
	*/
	size_t recv_ctr = 0;
	do {
		size_t record_len = recv_record(s);
#ifdef DEBUG
		printf("raw record: ");
		hexdump(recvbuf, record_len);
		printf("\n");
#endif
		if (recvbuf[0] != 23) { // the handshake records we want are pretending to be application traffic
			continue;
		}
		server_handshake_traffic_secret_iv[11] ^= recv_ctr; // xxx: assumes <256 messages!!!
		aes_gcm(recvbuf, ALG_OP_DECRYPT, server_handshake_traffic_secret_key, server_handshake_traffic_secret_iv, record_len, 5);
		server_handshake_traffic_secret_iv[11] ^= recv_ctr++;
#ifdef DEBUG
		printf("decrypted record: ");
		hexdump(recvbuf, record_len);
		printf("\n");
#endif
		DBG_ASSERT(recvbuf[record_len-16-1] == 22); // encapsulated handshake record (might need to make this a real check?)

		memcpy(transcript_buf+transcript_len, recvbuf+5, record_len-5-16-1); // skip over header, ignore auth tag and final type field
		transcript_len += record_len-5-16-1;

	} while (recvbuf[5] != 20); // "finished"

	/* find the new transcript hash */
	sha256(transcript_hash, transcript_buf, transcript_len);
#ifdef DEBUG
	printf("final transcript_hash: ");
	hexdump(transcript_hash, sizeof(transcript_hash));
	printf("\n");
#endif

	/* now we have everything required to derive the traffic keys */
	unsigned char master_secret[32];
	sha256(master_secret, (unsigned char*)"", 0); // buffer reuse
	hkdf_expand_label(master_secret, handshake_secret, "derived", master_secret, 32, 32); // buffer reuse
	hmac_sha256(master_secret, master_secret, H0, 32);
#ifdef DEBUG
	printf("master_secret: ");
	hexdump(master_secret, sizeof(master_secret));
	printf("\n");
#endif

	unsigned char client_application_traffic_secret_0[32];
	unsigned char client_application_traffic_secret_0_key[32];
	unsigned char client_application_traffic_secret_0_iv[32];
	hkdf_expand_label(client_application_traffic_secret_0, master_secret, "c ap traffic", transcript_hash, 32, 32);
	hkdf_expand_label(client_application_traffic_secret_0_key, client_application_traffic_secret_0, "key", NULL, 0, 16);
	hkdf_expand_label(client_application_traffic_secret_0_iv, client_application_traffic_secret_0, "iv", NULL, 0, 12);
#ifdef DEBUG
	printf("client_application_traffic_secret_0: ");
	hexdump(client_application_traffic_secret_0, sizeof(client_application_traffic_secret_0));
	printf("\n");
	printf("client_application_traffic_secret_0_key: ");
	hexdump(client_application_traffic_secret_0_key, 16);
	printf("\n");
	printf("client_application_traffic_secret_0_iv: ");
	hexdump(client_application_traffic_secret_0_iv, 12);
	printf("\n");
#endif

	unsigned char server_application_traffic_secret_0[32];
	unsigned char server_application_traffic_secret_0_key[32];
	unsigned char server_application_traffic_secret_0_iv[32];
	hkdf_expand_label(server_application_traffic_secret_0, master_secret, "s ap traffic", transcript_hash, 32, 32);
	hkdf_expand_label(server_application_traffic_secret_0_key, server_application_traffic_secret_0, "key", NULL, 0, 16);
	hkdf_expand_label(server_application_traffic_secret_0_iv, server_application_traffic_secret_0, "iv", NULL, 0, 12);
#ifdef DEBUG
	printf("server_application_traffic_secret_0: ");
	hexdump(server_application_traffic_secret_0, sizeof(server_application_traffic_secret_0));
	printf("\n");
	printf("server_application_traffic_secret_0_key: ");
	hexdump(server_application_traffic_secret_0_key, 16);
	printf("\n");
	printf("server_application_traffic_secret_0_iv: ");
	hexdump(server_application_traffic_secret_0_iv, 12);
	printf("\n");
#endif

	/* key derivation is complete !!!
		time to calculate and send finish data
	*/

	// finished_key = hkdf_expand_label(client_handshake_traffic_secret, b"finished", b"", 32)
	//	verify_data = hmac_digest(finished_key, self.transcript.digest())
	unsigned char finish_data[32];
	hkdf_expand_label(finish_data, client_handshake_traffic_secret, "finished", NULL, 0, 32);
	hmac_sha256(finish_data, finish_data, transcript_hash, 32);
#ifdef DEBUG
	printf("finish_data: ");
	hexdump(finish_data, sizeof(finish_data));
	printf("\n");
#endif

	// TODO: avoid this copy
	memcpy(CLIENT_FINISHED+9, finish_data, sizeof(finish_data));
	aes_gcm(CLIENT_FINISHED, ALG_OP_ENCRYPT, client_handshake_traffic_secret_key, client_handshake_traffic_secret_iv, sizeof(CLIENT_FINISHED)-16, 5);
#ifdef DEBUG
	printf("client_finished record: ");
	hexdump(CLIENT_FINISHED, sizeof(CLIENT_FINISHED));
	printf("\n");
#endif

	DBG_ASSERT(send(s, CLIENT_FINISHED, sizeof(CLIENT_FINISHED), 0) == sizeof(CLIENT_FINISHED)); // TODO: sendall

	/* WOOOOOO handshake is complete!!!!
	time to install the keys in ktls
	*/

	DBG_ASSERT(setsockopt(s, SOL_TCP, TCP_ULP, "tls", 3) == 0);
	ktls_set_key(s, TLS_TX, client_application_traffic_secret_0_key, client_application_traffic_secret_0_iv);
	ktls_set_key(s, TLS_RX, server_application_traffic_secret_0_key, server_application_traffic_secret_0_iv);
}

int main(int argc, char *argv[])
{
	unsigned char res[32];

#ifdef DEBUG
	printf("Hello, world!\n");


	sha256(res, (unsigned char*)"hello\n", strlen("hello\n")); // expected 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
	printf("test sha256: ");
	hexdump(res, sizeof(res));
	printf("\n");

	// incremental hashing does not work as I would have hoped (reading the result resets the state)
	int transcript = alg_sock("hash", "sha256"); // will be updated incrementally
	unsigned char transcript_hash[32];
	send(transcript, "a", 1, MSG_MORE);
	send(transcript, "b", 1, MSG_MORE);
	recv(transcript, transcript_hash, sizeof(transcript_hash), MSG_PEEK);
	printf("incremental sha256: ");
	hexdump(transcript_hash, sizeof(transcript_hash));
	printf("\n");
	send(transcript, "c", 1, MSG_MORE);
	recv(transcript, transcript_hash, 2, 0);
	printf("incremental sha256 (again): ");
	hexdump(transcript_hash, sizeof(transcript_hash));
	printf("\n");

	hmac_sha256(res, (unsigned char*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", (unsigned char*)"abc", strlen("abc")); // expected 7e2b3bd5ad0e797ae29d038e5146f5adb8487509c2208d8ca89e70681afd0a6f
	printf("test hmac: ");
	hexdump(res, sizeof(res));
	printf("\n");

	strcpy((char*)res, "xxABC");
	aes_gcm(res, ALG_OP_ENCRYPT, (unsigned char*)"AAAAAAAAAAAAAAAA", (unsigned char*)"AAAAAAAAAAAA", 5, 2);
	printf("encrypted: ");
	hexdump(res, 5+16);
	printf("\n");

	aes_gcm(res, ALG_OP_DECRYPT, (unsigned char*)"AAAAAAAAAAAAAAAA", (unsigned char*)"AAAAAAAAAAAA", 5+16, 2);
	printf("decrypted: ");
	hexdump(res, 5);
	printf("\n");
#endif

	int s = tcp_connect();
	tls13_handshake(s);

	const char REQ[] = "GET / HTTP/1.1\r\nHost: binary.golf\r\nConnection: close\r\n\r\n";
	DBG_ASSERT(send(s, REQ, strlen(REQ), 0) == strlen(REQ)); // TODO: sendall?
	//ssize_t recvlen = recv(s, recvbuf, sizeof(recvbuf), 0);
	//printf("recvd %ld\n", recvlen);

	int ret = 1;

	while (ret > 0)
	{
		char cmsg[CMSG_SPACE(sizeof(unsigned char))];
		struct msghdr msg = {0};
		msg.msg_control = cmsg;
		msg.msg_controllen = sizeof(cmsg);

		struct iovec msg_iov;
		msg_iov.iov_base = recvbuf;
		msg_iov.iov_len = sizeof(recvbuf);

		msg.msg_iov = &msg_iov;
		msg.msg_iovlen = 1;

		ret = recvmsg(s, &msg, 0);
		DBG_ASSERT(ret >= 0);

		struct cmsghdr *cmsgh = CMSG_FIRSTHDR(&msg);
		if (cmsgh && cmsgh->cmsg_level == SOL_TLS && cmsgh->cmsg_type == TLS_GET_RECORD_TYPE) {
			int record_type = *((unsigned char *)CMSG_DATA(cmsgh));
#ifdef DEBUG
			printf("[+] record type %d\n", record_type);
#endif
			if (record_type == 23) {
				fwrite(recvbuf, 1, ret, stdout);
			} else {
#ifdef DEBUG
				// session tickets, alerts (connection close)
				hexdump(recvbuf, ret);
				printf("\n");
#endif
			}
		} else {
			//DBG_ASSERT(0);
		}

	}
	
	
	return 0;
}
