/* GPL-2.0 */
/*
 * 
 * Authors:
 *   
 */

#ifndef __VENCYPTO_CRYPTO_H
#define __VENCYPTO_CRYPTO_H

#include <linux/crypto.h>         // for struct crypto_skcipher
#include <linux/scatterlist.h>    // for struct scatterlist
#include <linux/crypto.h>         // for struct crypto_wait
#include <crypto/skcipher.h>      // for struct skcipher_request
#include <linux/types.h>          // for bool and u8


struct cipher_ctx {
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct scatterlist sg;
	struct crypto_wait wait;
	u8 iv[16];
	u8 key[32]; // AES key (up to 256 bits)
};

unsigned int block_len_pkcs7(u8 *block, unsigned int block_size);

void pad_block_pkcs7(u8 *block, unsigned int current_length,
		     unsigned int block_size);

int setup_cipher_context(struct cipher_ctx *ctx,
			 const u8 *key, unsigned int keylen);

void zero_cipher_iv(struct cipher_ctx *ctx);
void random_cipher_iv(struct cipher_ctx *ctx);

void free_cipher_context(struct cipher_ctx *ctx);

int encrypt_block(struct cipher_ctx *ctx, u8 *block, const size_t block_length);
int decrypt_block(struct cipher_ctx *ctx, u8 *block, const size_t block_length);

#endif /* __VENCYPTO_CRYPTO_H */
