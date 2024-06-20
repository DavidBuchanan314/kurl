#include <stddef.h>

void *memset(void * restrict dst, int c, size_t n)
{
	char *d = dst;
	for (size_t i=0; i<n; i++) {
		d[i] = c;
	}
	return dst;
}
