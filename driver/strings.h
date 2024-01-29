#ifndef __VENCRYPT_STRINGS_H
#define __VENCRYPT_STRINGS_H

#include <linux/types.h>

int hex_to_bytes(u8 *dst, const char *src, unsigned int dst_size);

#endif /* __VENCRYPT_STRINGS_H */
