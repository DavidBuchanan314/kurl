//#define DEBUG 1

// google dns
#define DNS_SERVER 0x08080808
#define TLS_PORT 443



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

#define SYS_ERRNO ((int){0}) // dummy lvalue
#include "linux_syscall_support.h"

// these aren't in LSS, for whatever reason
LSS_INLINE _syscall5(int, setsockopt, int, sockfd, int, level, int, optname, const void*, optval, socklen_t, optlen)
LSS_INLINE _syscall3(int, bind, int, sockfd, const struct sockaddr *, addr, socklen_t, addrlen)
LSS_INLINE _syscall3(int, accept, int, sockfd, struct sockaddr *, addr, socklen_t *, addrlen)
LSS_INLINE _syscall3(int, connect, int, sockfd, const struct sockaddr *, addr, socklen_t, addrlen)


//#include <string.h>

//#include <assert.h>


#ifdef DEBUG
#define DBG_ASSERT(x) do { if (!(x)) {sys_write(1, "abort\n", 6); sys__exit(-1);} } while (0)
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

// this also contains the server name
//static const unsigned char DNS_REQ[] = {0xa4,0xb5,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x62,0x69,0x6e,0x61,0x72,0x79,0x04,0x67,0x6f,0x6c,0x66,0x00,0x00,0x01,0x00,0x01};

// nb: this contains the server name
//static const unsigned char CLIENT_HELLO[] = {0x16,0x03,0x03,0x00,0xa7,0x01,0x00,0x00,0xa3,0x03,0x03,0x6f,0x26,0x15,0xa1,0x08,0xc7,0x02,0xc5,0x67,0x8f,0x54,0xfc,0x9d,0xba,0xb6,0x97,0x16,0xc0,0x76,0x18,0x9c,0x48,0x25,0x0c,0xeb,0xea,0xc3,0x57,0x6c,0x36,0x11,0xba,0x00,0x00,0x02,0x13,0x01,0x01,0x00,0x00,0x78,0x00,0x2b,0x00,0x03,0x02,0x03,0x04,0x00,0x0a,0x00,0x04,0x00,0x02,0x00,0x17,0x00,0x0d,0x00,0x08,0x00,0x06,0x04,0x01,0x04,0x03,0x08,0x04,0x00,0x33,0x00,0x47,0x00,0x45,0x00,0x17,0x00,0x41,0x04,0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5,0x00,0x00,0x00,0x0e,0x00,0x0c,0x00,0x00,0x09,0x6c,0x6f,0x63,0x61,0x6c,0x68,0x6f,0x73,0x74};

// aaaactually let's just not do SNI lol (in violation of the tls1.3 spec)
static const unsigned char CLIENT_HELLO[] = {0x16,0x03,0x03,0x00,0x95,0x01,0x00,0x00,0x91,0x03,0x03,0x6f,0x26,0x15,0xa1,0x08,0xc7,0x02,0xc5,0x67,0x8f,0x54,0xfc,0x9d,0xba,0xb6,0x97,0x16,0xc0,0x76,0x18,0x9c,0x48,0x25,0x0c,0xeb,0xea,0xc3,0x57,0x6c,0x36,0x11,0xba,0x00,0x00,0x02,0x13,0x01,0x01,0x00,0x00,0x66,0x00,0x2b,0x00,0x03,0x02,0x03,0x04,0x00,0x0a,0x00,0x04,0x00,0x02,0x00,0x17,0x00,0x0d,0x00,0x08,0x00,0x06,0x04,0x01,0x04,0x03,0x08,0x04,0x00,0x33,0x00,0x47,0x00,0x45,0x00,0x17,0x00,0x41,0x04,0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};

// the "random" value in CLIENT_HELLO is otherwise unused. we slot the DERIVED_SECRET value in there to save space!
//static const unsigned char DERIVED_SECRET[32] = {0x6f,0x26,0x15,0xa1,0x08,0xc7,0x02,0xc5,0x67,0x8f,0x54,0xfc,0x9d,0xba,0xb6,0x97,0x16,0xc0,0x76,0x18,0x9c,0x48,0x25,0x0c,0xeb,0xea,0xc3,0x57,0x6c,0x36,0x11,0xba};
#define DERIVED_SECRET (CLIENT_HELLO+11)

static unsigned char H0[32]; // 32 zeroes 

static unsigned char recvbuf[0x10100]; // enough for 16-bit length, plus headers
static unsigned char transcript_buf[0x10000]; // 64k ought to be enough for anyone!
static size_t transcript_len = 0;

static int algfd; //reusable? socket(AF_ALG, SOCK_SEQPACKET, 0);

struct skiv {
	unsigned char secret[32];
	unsigned char key[32];
	unsigned char iv[32];
};


/* begin mini libc impl */
// TODO: figure out how to make this static...
void *memcpy(void * restrict dst, const void * restrict src, size_t n)
{
	char *d = dst;
	const char *s = src;
	for (size_t i=0; i<n; i++) {
		d[i] = s[i];
	}
	return dst;
}

size_t strlen(const char *s)
{
	size_t i = 0;
	while (s[i]) i++;
	return i;
}

char *strcpy(char * restrict dst, const char * restrict src)
{
	size_t i = 0;
	do {
		dst[i] = src[i];
	} while (src[i++]);
	return dst+i-1;
}

#undef CMSG_NXTHDR
#define CMSG_NXTHDR(mhdr, cmsg) ((struct cmsghdr *) ((unsigned char *) cmsg + CMSG_ALIGN(cmsg->cmsg_len)))

// only here for debugging
#ifdef DEBUG
static void hexdump(unsigned char *buf, size_t len)
{
	char tmp[2];
	for (size_t i=0; i<len; i++) {
		tmp[0] = "0123456789abcdef"[buf[i]>>4];
		tmp[1] = "0123456789abcdef"[buf[i]&0xf];
		sys_write(1, tmp, 2);
	}
}

int printf(const char * restrict fmt, ...)
{
	sys_write(1, fmt, strlen(fmt));
}
#endif

/* end mini libc impl */

static int alg_sock(const char *type, const char *name)
{
	algfd = sys_socket(AF_ALG, SOCK_SEQPACKET, 0); // actually we need a new one each time????
	DBG_ASSERT(algfd >= 0);
	struct sockaddr_alg sa;
	sa.salg_family = AF_ALG;
	strcpy((char*)sa.salg_type, type);
	sa.salg_mask = 0;
	sa.salg_feat = 0;
	strcpy((char*)sa.salg_name, name);
	DBG_ASSERT(sys_bind(algfd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	int res = sys_accept(algfd, NULL, 0);
	DBG_ASSERT(res >= 0);
	return res;
}

// aka hkdf_extract(salt, ikm)
// if key==NULL, it's just regular sha256
static void hmac_sha256(unsigned char *res, unsigned char key[32], unsigned char *data, size_t len)
{
	int sfd = alg_sock("hash", key ? "hmac(sha256)" : "sha256");
	if (key) sys_setsockopt(algfd, SOL_ALG, ALG_SET_KEY, key, 32);
	DBG_ASSERT(sys_write(sfd, data, len) == (ssize_t)len);
	DBG_ASSERT(sys_read(sfd, res, 32) == 32);
	// XXX: leaks sfd
}

// nb: will always fill 32 bytes of res (maybe)
static void hkdf_expand_label(unsigned char *res, unsigned char secret[32], char *label, unsigned char *ctx, size_t ctxlen, size_t len)
{
	// this is really gross and will need to be mostly rewritten when we ditch libc
	unsigned char buf[0x100];
	buf[0] = 0;
	buf[1] = len;
	unsigned char *ptr = (unsigned char*)strcpy(strcpy((char*)buf+3, "tls13 "), label);
	buf[2] = ptr-buf-3;
	*ptr++ = ctxlen;
	memcpy(ptr, ctx, ctxlen);
	ptr += ctxlen;
#ifdef DEBUG
	//printf("hkdf_expand_label buf (len=%lu): ", ptr);
	//hexdump(buf, ptr);
	//printf("\n");
#endif
	*ptr++ = 1; // hkdf_expand counter suffix
	hmac_sha256(res, secret, buf, ptr-buf);
}

/* nb: this encrypts/decrypts "in place". length includes AD len, and tag len for decrypts */
static void aes_gcm(unsigned char *buf, int op, struct skiv *ski, size_t len, size_t adlen)
{
	int sfd = alg_sock("aead", "gcm(aes)");
	sys_setsockopt(algfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, 16);
	sys_setsockopt(algfd, SOL_ALG, ALG_SET_KEY, ski->key, 16);

	char cbuf[CMSG_SPACE(4) + CMSG_SPACE(4) + CMSG_SPACE(4+12)];// = {0};
	struct kernel_iovec iov = {
		.iov_base = buf,
		.iov_len = len,
	};
	struct kernel_msghdr msg;/* = {
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),

		.msg_iov = &iov,
		.msg_iovlen = 1,
	};*/
	msg.msg_namelen = 0;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	//msg.msg_flags = 0;

	struct cmsghdr *cmsg;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(uint32_t *)CMSG_DATA(cmsg) = op;

	cmsg = CMSG_NXTHDR((struct msghdr *)&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(uint32_t *)CMSG_DATA(cmsg) = adlen;

	cmsg = CMSG_NXTHDR((struct msghdr *)&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(4+12);
	struct af_alg_iv *aiv = (void *)CMSG_DATA(cmsg);
	aiv->ivlen = 12;
	memcpy(aiv->iv, ski->iv, 12);

	DBG_ASSERT(sys_sendmsg(sfd, &msg, 0) >= 0);
	ssize_t reslen = op == ALG_OP_ENCRYPT ? len + 16 : len - 16;
	DBG_ASSERT(sys_read(sfd, buf, reslen) == reslen);
}

static int do_connect(int sock_type, uint32_t ip, int port)
{
	int s = sys_socket(AF_INET, sock_type, 0);
	DBG_ASSERT(s >= 0);
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = ip,
		.sin_port = port,
	};
	DBG_ASSERT(sys_connect(s, (struct sockaddr*)&sin, sizeof(sin)) == 0);
	return s;
}

static uint32_t do_dns(const char *hostname)
{
	char pkt[1024];
	// nb: first two bytes of pkt (id) are undefined. this is fine.
	// TODO: size-optimise these writes
	*(uint16_t*)(pkt+2) = htons(0x0100); // query
	*(uint16_t*)(pkt+4) = htons(0x0001); // 1 question
	*(uint16_t*)(pkt+6) = htons(0x0000); // 0 answers
	*(uint16_t*)(pkt+8) = htons(0x0000); // 0 of whatever these are
	*(uint16_t*)(pkt+10) = htons(0x0000); // likewise
	size_t idx = 13, start = 12;
	while (1) {
		if (*hostname <= '.') { // hack to include nul
			pkt[start] = idx - start - 1;
			start = idx++;
			if (!*hostname++) break;
		} else {
			pkt[idx++] = *hostname++;
		}
	}
	*(uint16_t*)(pkt+idx) = htons(0x0001);
	*(uint16_t*)(pkt+idx+2) = htons(0x0001);
	idx += 4;

#ifdef DEBUG
	printf("dns req: ");
	hexdump(pkt, idx);
	printf("\n");
#endif

	int s = do_connect(SOCK_DGRAM, DNS_SERVER, htons(53));
	DBG_ASSERT(sys_write(s, pkt, idx) == idx);
	size_t tmp = sys_read(s, recvbuf, sizeof(recvbuf));
	DBG_ASSERT(tmp > 0);

#ifdef DEBUG
	printf("dns res: ");
	hexdump(recvbuf, tmp);
	printf("\n");
#endif

	// scan for an "A" response (this is just a heuristic lol)
	while (*(uint32_t*)(recvbuf+idx) != 0x01000100) idx++;

	// skip over ttl, data length
	uint32_t ip = *(uint32_t*)(recvbuf+idx+10); 
	return ip;
}


#if 1
//this version is more correct (on the first read?), but takes like 40 extra bytes
static void recvall(int s, unsigned char *buf, size_t len)
{
	size_t ptr = 0;
	while (ptr < len)
	{
		size_t readlen = sys_read(s, buf+ptr, len - ptr);
		DBG_ASSERT(readlen > 0); // XXX: will infinite loop on EOF!
		ptr += readlen;
	}
	DBG_ASSERT(ptr == len);
}

static size_t recv_record(int s)
{
	recvall(s, recvbuf, 5);
	ssize_t msglen = (recvbuf[3]<<8) + recvbuf[4];
	recvall(s, recvbuf+5, msglen);
	return 5 + msglen;
}
#else

// receive the next record into recvbuf. does not account for record fragmentation.
// returns number of bytes of recvbuf populated (includes header)
static size_t recv_record(int s)
{
	ssize_t ptr = sys_read(s, recvbuf, 5); // TODO: make sure all bytes read?
	DBG_ASSERT(ptr == 5);
	ssize_t msglen = (recvbuf[3]<<8) + recvbuf[4] + 5;
	while (ptr < msglen)
	{
		size_t readlen = sys_read(s, recvbuf+ptr, msglen - ptr);
		DBG_ASSERT(readlen > 0); // XXX: will infinite loop on EOF!
		ptr += readlen;
	}
	DBG_ASSERT(ptr == msglen);
	return ptr;
}
#endif

static void ktls_set_key(int s, int direction, struct skiv *ski)
{
	struct tls12_crypto_info_aes_gcm_128 crypto_info = {
		.info.version = TLS_1_3_VERSION,
		.info.cipher_type = TLS_CIPHER_AES_GCM_128,
		.rec_seq = {0}
	};
	//memcpy(crypto_info.iv, iv+4, 8);
	*(uint64_t*)crypto_info.iv = *(uint64_t*)(ski->iv+4);
	memcpy(crypto_info.key, ski->key, 16);
	//memcpy(crypto_info.salt, iv, 4);
	*(uint32_t*)crypto_info.salt = *(uint32_t*)ski->iv;
	DBG_ASSERT(sys_setsockopt(s, SOL_TLS, direction, &crypto_info, sizeof(crypto_info)) == 0);
}

static void derive_key_iv(struct skiv *ski, unsigned char seed[32], uint32_t ctx, unsigned char transcript_hash[32])
{
	unsigned char buf[13];
	*(uint32_t*)buf = ctx;
	*(uint64_t *)(buf+4) = 0x6369666661727420; // " traffic"
	buf[12] = 0;
	hkdf_expand_label(ski->secret, seed, buf, transcript_hash, 32, 32);
	hkdf_expand_label(ski->key, ski->secret, "key", NULL, 0, 16);
	hkdf_expand_label(ski->iv, ski->secret, "iv", NULL, 0, 12);
}

static void tls13_handshake(int s)
{
	//int transcript = alg_sock("hash", "sha256"); // will be updated incrementally
	unsigned char transcript_hash[32];
	unsigned char dh_secret[32];

	/* SEND CLIENT HELLO (and update transcript) */
	DBG_ASSERT(sys_write(s, CLIENT_HELLO, sizeof(CLIENT_HELLO)) == sizeof(CLIENT_HELLO)); // TODO: make sure it all gets sent at once?
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
	hmac_sha256(transcript_hash, NULL, transcript_buf, transcript_len);

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
	struct skiv client_handshake_traffic;
	derive_key_iv(&client_handshake_traffic, handshake_secret, 0x73682063, transcript_hash);
#ifdef DEBUG
	printf("client_handshake_traffic_secret: ");
	hexdump(client_handshake_traffic.secret, 32);
	printf("\n");
	printf("client_handshake_traffic_secret_key: ");
	hexdump(client_handshake_traffic.key, 16);
	printf("\n");
	printf("client_handshake_traffic_secret_iv: ");
	hexdump(client_handshake_traffic.iv, 12);
	printf("\n");
#endif

	struct skiv server_handshake_traffic;
	derive_key_iv(&server_handshake_traffic, handshake_secret, 0x73682073, transcript_hash);
#ifdef DEBUG
	printf("server_handshake_traffic_secret: ");
	hexdump(server_handshake_traffic.secret, 32);
	printf("\n");
	printf("server_handshake_traffic_secret_key: ");
	hexdump(server_handshake_traffic.key, 16);
	printf("\n");
	printf("server_handshake_traffic_secret_iv: ");
	hexdump(server_handshake_traffic.iv, 12);
	printf("\n");
#endif

	/*
	loop through server handshake records, decrypt them, and add the plaintexts to
	the transcript buffer. break once the finish record is reached.
	*/
	size_t recv_ctr = 0;
	while (1) {
		size_t record_len = recv_record(s);
#ifdef DEBUG
		printf("raw record: ");
		hexdump(recvbuf, record_len);
		printf("\n");
#endif
		if (recvbuf[0] != 23) { // the handshake records we want are pretending to be application traffic
			continue;
		}
		server_handshake_traffic.iv[11] ^= recv_ctr; // xxx: assumes <256 messages!!!
		aes_gcm(recvbuf, ALG_OP_DECRYPT, &server_handshake_traffic, record_len, 5);
		server_handshake_traffic.iv[11] ^= recv_ctr++;
#ifdef DEBUG
		printf("decrypted record: ");
		hexdump(recvbuf, record_len);
		printf("\n");
#endif
		DBG_ASSERT(recvbuf[record_len-16-1] == 22); // encapsulated handshake record (might need to make this a real check?)

		// we need to scan thru until we reach the end, or find a finish record
		size_t ptr = 5;
		while (ptr < record_len - 1 - 16) {
			size_t thislen = (recvbuf[ptr+1]<<16) + (recvbuf[ptr+2]<<8) + recvbuf[ptr+3];
			memcpy(transcript_buf+transcript_len, recvbuf+ptr, 4+thislen); // skip over header, ignore auth tag and final type field
			transcript_len += 4+thislen;
			if (recvbuf[ptr] == 20) {
				goto found_finished;
			}
			ptr += 4+thislen;
		}

	};
found_finished:

	/* find the new transcript hash */
	hmac_sha256(transcript_hash, NULL, transcript_buf, transcript_len);
#ifdef DEBUG
	printf("final transcript_hash: ");
	hexdump(transcript_hash, sizeof(transcript_hash));
	printf("\n");
#endif

	/* now we have everything required to derive the traffic keys */
	unsigned char master_secret[32];
	hmac_sha256(master_secret, NULL, (unsigned char*)"", 0); // buffer reuse
	hkdf_expand_label(master_secret, handshake_secret, "derived", master_secret, 32, 32); // buffer reuse
	hmac_sha256(master_secret, master_secret, H0, 32);
#ifdef DEBUG
	printf("master_secret: ");
	hexdump(master_secret, sizeof(master_secret));
	printf("\n");
#endif

	struct skiv client_application_traffic;
	derive_key_iv(&client_application_traffic, master_secret, 0x70612063, transcript_hash);
#ifdef DEBUG
	printf("client_application_traffic_secret_0: ");
	hexdump(client_application_traffic.secret, 32);
	printf("\n");
	printf("client_application_traffic_secret_0_key: ");
	hexdump(client_application_traffic.key, 16);
	printf("\n");
	printf("client_application_traffic_secret_0_iv: ");
	hexdump(client_application_traffic.iv, 12);
	printf("\n");
#endif

	struct skiv server_application_traffic;
	derive_key_iv(&server_application_traffic, master_secret, 0x70612073, transcript_hash);
#ifdef DEBUG
	printf("server_application_traffic_secret_0: ");
	hexdump(server_application_traffic.secret, 32);
	printf("\n");
	printf("server_application_traffic_secret_0_key: ");
	hexdump(server_application_traffic.key, 16);
	printf("\n");
	printf("server_application_traffic_secret_0_iv: ");
	hexdump(server_application_traffic.iv, 12);
	printf("\n");
#endif

	/* key derivation is complete !!!
		time to calculate and send finish data
	*/

	//unsigned char finish_data[32];
	unsigned char client_finished[58];// = {0x17,0x03,0x03,0x00,0x35, 0x14,0x00,0x00,0x20};
	*(uint32_t*)(client_finished+0) = 0x00030317;
	*(uint32_t*)(client_finished+4) = 0x00001435;
	client_finished[8] = 0x20;
	hkdf_expand_label(client_finished+9, client_handshake_traffic.secret, "finished", NULL, 0, 32);
	hmac_sha256(client_finished+9, client_finished+9, transcript_hash, 32);
	client_finished[41] = 0x16;
#ifdef DEBUG
	printf("finish_data: ");
	hexdump(client_finished+9, 32);
	printf("\n");
#endif

	aes_gcm(client_finished, ALG_OP_ENCRYPT, &client_handshake_traffic, sizeof(client_finished)-16, 5);
#ifdef DEBUG
	printf("client_finished record: ");
	hexdump(client_finished, sizeof(client_finished));
	printf("\n");
#endif

	DBG_ASSERT(sys_write(s, client_finished, sizeof(client_finished)) == sizeof(client_finished)); // TODO: sendall

	/* WOOOOOO handshake is complete!!!!
	time to install the keys in ktls
	*/

	DBG_ASSERT(sys_setsockopt(s, SOL_TCP, TCP_ULP, "tls", 3) == 0);
	ktls_set_key(s, TLS_TX, &client_application_traffic);
	ktls_set_key(s, TLS_RX, &server_application_traffic);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
show_usage:
		sys_write(1, "USAGE: ./kurl https://url\n", 26);
		return 0;
	}
	if (*(uint64_t*)argv[1] != 0x2f2f3a7370747468) { // "https://"
		goto show_usage;
	}
	unsigned char *hostname = argv[1]+8; // len("https://")
	unsigned char *path = hostname;
	while (*path && *path != '/') path++;
	if (*path) *path++ = 0; // also handles empty path (hostname with no trailing slash)

#ifdef DEBUG
	unsigned char res[32];

	printf(argv[0]);
	//hexdump(argv, 16);
	printf("\n");

	printf("Hello, world!\n");
	//sys__exit(0);


	hmac_sha256(res, NULL, (unsigned char*)"hello\n", strlen("hello\n")); // expected 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
	printf("test sha256: ");
	hexdump(res, sizeof(res));
	printf("\n");

	// incremental hashing does not work as I would have hoped (reading the result resets the state)
	/*int transcript = alg_sock("hash", "sha256"); // will be updated incrementally
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
	printf("\n");*/

	hmac_sha256(res, (unsigned char*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", (unsigned char*)"abc", strlen("abc")); // expected 7e2b3bd5ad0e797ae29d038e5146f5adb8487509c2208d8ca89e70681afd0a6f
	printf("test hmac: ");
	hexdump(res, sizeof(res));
	printf("\n");

	struct skiv keyz = {
		.key = "AAAAAAAAAAAAAAAA",
		.iv = "AAAAAAAAAAAA"
	};
	strcpy((char*)res, "xxABC");
	aes_gcm(res, ALG_OP_ENCRYPT, &keyz, 5, 2);
	printf("encrypted: ");
	hexdump(res, 5+16);
	printf("\n");

	aes_gcm(res, ALG_OP_DECRYPT, &keyz, 5+16, 2);
	printf("decrypted: ");
	hexdump(res, 5);
	printf("\n");
#endif

	uint32_t ip = do_dns(hostname);
#ifdef DEBUG
	printf("ip: ");
	hexdump((unsigned char*)&ip, 4);
	printf("\n");
	//sys__exit(0);
#endif
	int s = do_connect(SOCK_STREAM, ip, htons(TLS_PORT));
	tls13_handshake(s);

	char req[1024];// = "GET /5/5 HTTP/1.1\r\nHost: binary.golf\r\nConnection: close\r\n\r\n";
	char *req_end = strcpy(strcpy(strcpy(strcpy(strcpy(req, "GET /"), path), " HTTP/1.1\r\nHost: "), hostname), "\r\nConnection: close\r\n\r\n");
	DBG_ASSERT(sys_write(s, req, req_end-req) == strlen(req)); // TODO: sendall?
	//ssize_t recvlen = recv(s, recvbuf, sizeof(recvbuf), 0);
	//printf("recvd %ld\n", recvlen);

	int ret = 1;

	while (ret > 0)
	{
		char cmsg[CMSG_SPACE(sizeof(unsigned char))];
		struct kernel_msghdr msg;// = {0};
		msg.msg_namelen = 0;
		msg.msg_control = cmsg;
		msg.msg_controllen = sizeof(cmsg);

		struct kernel_iovec msg_iov;
		msg_iov.iov_base = recvbuf;
		msg_iov.iov_len = sizeof(recvbuf);

		msg.msg_iov = &msg_iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;

		ret = sys_recvmsg(s, &msg, 0);
		DBG_ASSERT(ret >= 0);

		struct cmsghdr *cmsgh = CMSG_FIRSTHDR(&msg);
		if (cmsgh && cmsgh->cmsg_level == SOL_TLS && cmsgh->cmsg_type == TLS_GET_RECORD_TYPE) {
			int record_type = *((unsigned char *)CMSG_DATA(cmsgh));
#ifdef DEBUG
			printf("[+] record type %d\n", record_type);
#endif
			if (record_type == 23) {
				sys_write(1, recvbuf, ret);
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

/*
void _start(void)
{
	void **auxv = __builtin_frame_address(0) + 16; // XXX: you may need to tweak this!
	sys__exit(main(*(int*)auxv, (char **)auxv+1)); 
	__builtin_unreachable();
}
*/
