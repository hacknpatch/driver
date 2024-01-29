#ifndef __VENCRYPT_CRYPTO_H
#define __VENCRYPT_CRYPTO_H

#include <linux/crypto.h> // for struct crypto_skcipher
#include <linux/scatterlist.h> // for struct scatterlist
#include <linux/crypto.h> // for struct crypto_wait
#include <crypto/skcipher.h> // for struct skcipher_request
#include <linux/types.h> // for bool and u8

#define AES_MIN_KEY_SIZE 16
#define AES_MAX_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define AES_IV_SIZE 16

struct venc_cipher {
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct scatterlist sg;
	struct crypto_wait wait;
	u8 iv[AES_IV_SIZE];
	u8 key[AES_MAX_KEY_SIZE];
};

size_t pkcs7_block_len(u8 *block, size_t block_size);
void pkcs7_pad_block(u8 *block, size_t current_size, size_t block_size);

int venc_init_cipher(struct venc_cipher *cipher, const u8 *key,
		     unsigned int keylen);
void venc_free_cipher(struct venc_cipher *cipher);

void venc_zero_cipher_iv(struct venc_cipher *cipher);
void venc_random_cipher_iv(struct venc_cipher *cipher);

int venc_encrypt(struct venc_cipher *cipher, u8 *block,
		 const size_t block_length);
int venc_decrypt(struct venc_cipher *cipher, u8 *block,
		 const size_t block_length);

#endif /* __VENCRYPT_CRYPTO_H */
