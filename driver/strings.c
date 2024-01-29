#include <linux/string.h>
#include <linux/errno.h>

#include "strings.h"

static int char_to_nibble(char c)
{
	if ('0' <= c && c <= '9')
		return (u8)(c - '0');
	if ('A' <= c && c <= 'F')
		return (u8)(c - 'A' + 10);
	if ('a' <= c && c <= 'f')
		return (u8)(c - 'a' + 10);
	return -EINVAL;
}

int hex_to_bytes(u8 *dst, const char *src, unsigned int dst_size)
{
	size_t i, l;
	int ms, ls;

	l = strlen(src);
	if (src[0] == '\0' || l % 2)
		return -EINVAL;
	if (l > dst_size * 2)
		return -EINVAL;
	memset(dst, 0, dst_size);

	for (i = 0; i < l; i += 2) {
		ms = char_to_nibble(src[i]);
		if (ms < 0)
			return -EINVAL;
		ls = char_to_nibble(src[i + 1]);
		if (ls < 0)
			return -EINVAL;
		dst[i / 2] = (ms << 4) | ls;
	}
	return 0;
}
