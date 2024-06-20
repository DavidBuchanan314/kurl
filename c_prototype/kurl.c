#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_alg.h>
#include <linux/socket.h>

#include <string.h>

#include <assert.h>

#define DEBUG 1

#ifdef DEBUG
#define DBG_ASSERT(x) assert(x)
#else
#define DBG_ASSERT(x) do { if (x) {} } while (0)
#endif

/*
Useful reference: https://github.com/smuellerDD/libkcapi

https://github.com/nibrunie/af_alg-examples

General notes:
- There's a big lack of error handling!
- There are lots of fd leaks!
- These things are both fine because we're code golfing ;)

TODO: consider replacing send/recv with write/read, when flag is 0
*/

// nb: this contains the server name
static const unsigned char CLIENT_HELLO[] = {0x16,0x03,0x03,0x00,0xa7,0x01,0x00,0x00,0xa3,0x03,0x03,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x00,0x00,0x02,0x13,0x01,0x01,0x00,0x00,0x78,0x00,0x2b,0x00,0x03,0x02,0x03,0x04,0x00,0x0a,0x00,0x04,0x00,0x02,0x00,0x17,0x00,0x0d,0x00,0x08,0x00,0x06,0x04,0x01,0x04,0x03,0x08,0x04,0x00,0x33,0x00,0x47,0x00,0x45,0x00,0x17,0x00,0x41,0x04,0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5,0x00,0x00,0x00,0x0e,0x00,0x0c,0x00,0x00,0x09,0x6c,0x6f,0x63,0x61,0x6c,0x68,0x6f,0x73,0x74};

static unsigned char recvbuf[0x10100]; // enough for 16-bit length, plus headers

static int algfd; //reusable? socket(AF_ALG, SOCK_SEQPACKET, 0);

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

static void sha256(unsigned char *res, unsigned char *buf, size_t len)
{	
	int sfd = alg_sock("hash", "sha256");
	DBG_ASSERT(send(sfd, buf, len, 0) == (ssize_t)len);
	DBG_ASSERT(recv(sfd, res, 32, 0) == 32);
	// XXX: leaks sfd
}

// aka hkdf_extract(salt, ikm)
static void hmac_sha256(unsigned char *res, unsigned char *key, unsigned char *data, size_t len)
{
	int sfd = alg_sock("hash", "hmac(sha256)");
	setsockopt(algfd, SOL_ALG, ALG_SET_KEY, key, 32);
	DBG_ASSERT(send(sfd, data, len, 0) == (ssize_t)len);
	DBG_ASSERT(recv(sfd, res, 32, 0) == 32);
	// XXX: leaks sfd
}

/* should maybe have an enc/dec flag */
static void aes_gcm_dec(char *res, char *key, char *iv, char *data, size_t len)
{
	int sfd = alg_sock("aead", "gcm(aes)");
	//setsockopt(algfd, SOL_ALG, ALG_SET_OP, NULL, ALG_OP_DECRYPT);
	setsockopt(algfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 16);
	setsockopt(algfd, SOL_ALG, ALG_SET_KEY, key, 16);
	//setsockopt(sfd, SOL_ALG, ALG_SET_IV, iv, 12);
	// sendmsg sets iv
	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20)] = {0};
	struct iovec iov = {
		.iov_base = data,
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),

		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	// TODO: finish this!!!
	DBG_ASSERT(sendmsg(sfd, &msg, 0) >= 0); // this fails, for now
}

// only here for debugging
static void hexdump(unsigned char *buf, size_t len)
{
	for (size_t i=0; i<len; i++) {
		printf("%02x", (unsigned char)buf[i]);
	}
}

static int tcp_connect(void)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	DBG_ASSERT(s >= 0);
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
		.sin_port = htons(1337),
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

static void tls13_handshake(int s)
{
	int transcript = alg_sock("hash", "sha256"); // will be updated incrementally
	unsigned char transcript_hash[32];
	unsigned char dh_secret[32];

	/* SEND CLIENT HELLO (and update transcript) */
	DBG_ASSERT(send(s, CLIENT_HELLO, sizeof(CLIENT_HELLO), 0) == sizeof(CLIENT_HELLO)); // TODO: make sure it all gets sent at once?
	DBG_ASSERT(send(transcript, CLIENT_HELLO+5, sizeof(CLIENT_HELLO)-5, 0) == sizeof(CLIENT_HELLO)-5);

	/* RECEIVE SERVER HELLO (and update transcript) */
	size_t server_hello_len = recv_record(s); // read the server hello into recvbuf
#ifdef DEBUG
	printf("server hello (len=%lu): ", server_hello_len);
	hexdump(recvbuf, server_hello_len);
	printf("\n");
#endif
	DBG_ASSERT(recvbuf[0] == 22); // is handshake msg
	DBG_ASSERT(recvbuf[5] == 2); // is server hello
	DBG_ASSERT(send(transcript, recvbuf+5, server_hello_len-5, 0) == (ssize_t)server_hello_len-5);

	/* grab the current transcript hash state */
	DBG_ASSERT(recv(transcript, transcript_hash, sizeof(transcript_hash), 0) == sizeof(transcript_hash));

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

	hmac_sha256(res, (unsigned char*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", (unsigned char*)"abc", strlen("abc")); // expected 7e2b3bd5ad0e797ae29d038e5146f5adb8487509c2208d8ca89e70681afd0a6f
	printf("test hmac: ");
	hexdump(res, sizeof(res));
	printf("\n");

	//aes_gcm_dec(res, "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAA", "", 0);
	//hexdump(res, sizeof(res));
	//printf("\n");
#endif

	int s = tcp_connect();
	tls13_handshake(s);
	
	return 0;
}
