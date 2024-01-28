#ifndef __VENCYPTO_CRYPTO_H
#define __VENCYPTO_CRYPTO_H

#include <linux/crypto.h>         // for struct crypto_skcipher
#include <linux/scatterlist.h>    // for struct scatterlist
#include <linux/crypto.h>         // for struct crypto_wait
#include <crypto/skcipher.h>      // for struct skcipher_request
#include <linux/types.h>          // for bool and u8

#define CBC_AES_MIN_KEY_SIZE 16
#define CBC_AES_MAX_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_IV_SIZE 16

struct vencrypt_cipher {
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct scatterlist sg;
	struct crypto_wait wait;
	u8 iv[AES_IV_SIZE];
	u8 key[CBC_AES_MAX_KEY_SIZE];
};

size_t block_len_pkcs7(u8 *block, size_t block_size);
void pad_block_pkcs7(u8 *block, size_t current_size, size_t block_size);

int init_cipher(struct vencrypt_cipher *cipher,
			 const u8 *key, unsigned int keylen);

void zero_cipher_iv(struct vencrypt_cipher *cipher);
void random_cipher_iv(struct vencrypt_cipher *cipher);

void free_cipher(struct vencrypt_cipher *cipher);

int encrypt_block(struct vencrypt_cipher *cipher, u8 *block, const size_t block_length);
int decrypt_block(struct vencrypt_cipher *cipher, u8 *block, const size_t block_length);

#endif /* __VENCYPTO_CRYPTO_H */
