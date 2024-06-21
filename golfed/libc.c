#include <stddef.h>

void *memcpy(void * restrict dst, const void * restrict src, size_t n)
{
	char *d = dst;
	const char *s = src;
	for (size_t i=0; i<n; i++) {
		d[i] = s[i];
	}
	return dst;
}
