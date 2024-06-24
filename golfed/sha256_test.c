#include "linux_syscall_support.h"

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

void *memset(void * restrict s, int c, size_t n)
{
	char *dst = s;
	for (size_t i=0; i<n; i++) {
		dst[i] = 0;
	}
	return s;
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

static void hexdump(unsigned char *buf, size_t len)
{
	char tmp[2];
	for (size_t i=0; i<len; i++) {
		tmp[0] = "0123456789abcdef"[buf[i]>>4];
		tmp[1] = "0123456789abcdef"[buf[i]&0xf];
		sys_write(1, tmp, 2);
	}
}

static void bufswap32(unsigned char *buf, size_t len)
{
	for (size_t i=0; i<len; i+=4) {
		*(uint32_t*)(buf+i) = __builtin_bswap32(*(uint32_t*)(buf+i));
	}
}

/*
Based on https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-arm.c
*/

#if defined(__arm__) || defined(__aarch32__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM)
# if defined(__GNUC__)
#  include <stdint.h>
# endif
# if defined(__ARM_NEON) || defined(_MSC_VER) || defined(__GNUC__)
#  include <arm_neon.h>
# endif
/* GCC and LLVM Clang, but not Apple Clang */
# if defined(__GNUC__) && !defined(__apple_build_version__)
#  if defined(__ARM_ACLE) || defined(__ARM_FEATURE_CRYPTO)
#   include <arm_acle.h>
#  endif
# endif
#endif  /* ARM Headers */

static const uint32_t K[] =
{
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

/* Process multiple blocks. The caller is responsible for setting the initial */
/*  state, and the caller is responsible for padding the final block.		*/

// I'm only noinline-ing this to get an idea of how big the function is on its own
void __attribute__((noinline)) sha256_process_arm(uint32_t state[8], const uint8_t data[], uint32_t length)
{
	uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
	uint32x4_t MSG[4];
	uint32x4_t TMP0, TMP2;

	/* Load state */
#if 0
	STATE0 = (uint32x4_t){0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a};
	STATE1 = (uint32x4_t){0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
#else
	STATE0 = vld1q_u32(&state[0]);
	STATE1 = vld1q_u32(&state[4]);
#endif

	while (length >= 64)
	{
		/* Save state */
		ABEF_SAVE = STATE0;
		CDGH_SAVE = STATE1;

		/* Load message */
		// for some reason these three methods end up identical in byte count lol
		for (int i=0; i<4; i++) {
			MSG[i] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32((const uint32_t *)(data +  i*16)))));
		}
		//memcpy((void*)MSG, data, sizeof(MSG));

		/*MSG[0] = vld1q_u32((const uint32_t *)(data +  0*16));
		MSG[1] = vld1q_u32((const uint32_t *)(data +  1*16));
		MSG[2] = vld1q_u32((const uint32_t *)(data +  2*16));
		MSG[3] = vld1q_u32((const uint32_t *)(data +  3*16));*/
		//MSG = data; // clobbers data

		for (int i=0; i<16; i++) {
			TMP0 = vaddq_u32(MSG[(i+0)&3], vld1q_u32(&K[i*4]));
			TMP2 = STATE0;
			STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
			STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
			MSG[(i+0)&3] = vsha256su1q_u32(vsha256su0q_u32(MSG[(i+0)&3], MSG[(i+1)&3]), MSG[(i+2)&3], MSG[(i+3)&3]);
		}

		/* Combine state */
		STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
		STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

		data += 64;
		length -= 64;
	}

	/* Save state */
	vst1q_u32(&state[0], vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(STATE0))));
	vst1q_u32(&state[4], vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(STATE1))));
}

int main(int argc, char *argv[])
{
	//sys_write(1, "Hello, world!\n", sizeof("Hello, world!\n")-1);
	uint8_t message[64];
	memset(message, 0x00, sizeof(message));
	message[0] = 0x80;

	/* initial state */
#if 0
	uint32_t state[8];
#else
	uint32_t state[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
#endif
	//bufswap32(message, sizeof(message));
	sha256_process_arm(state, message, sizeof(message));
	//bufswap32((void*)state, sizeof(state));
	hexdump((void*)state, sizeof(state));
	sys_write(1, "\n", 1);
	return 0;
}
