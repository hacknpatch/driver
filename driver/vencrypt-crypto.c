#include <linux/random.h>
#include <linux/string.h>

#include "vencrypt-crypto.h"


/*
 * 
 * name         : cbc(aes)
 * driver       : cbc-aes-aesni
 * module       : aesni_intel
 * priority     : 400
 * refcnt       : 1
 * selftest     : passed
 * internal     : no
 *  type         : skcipher
 * async        : yes
 * blocksize    : 16
 * min keysize  : 16
 * max keysize  : 32
 * ivsize       : 16
 * chunksize    : 16
 * walksize     : 16
 */


void free_cipher(struct vencrypt_cipher *cipher)
{
	if (cipher->req)
		skcipher_request_free(cipher->req);
	if (cipher->tfm)
		crypto_free_skcipher(cipher->tfm);
}

int init_cipher(struct vencrypt_cipher *cipher,
			 const u8 *key, unsigned int keylen)
{
	int ret;

	cipher->tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(cipher->tfm)) {
		pr_err("Error allocating cipher handle: %ld\n",
		       PTR_ERR(cipher->tfm));
		return PTR_ERR(cipher->tfm);
	}

	cipher->req = skcipher_request_alloc(cipher->tfm, GFP_KERNEL);
	if (!cipher->req) {
		pr_err("Failed to allocate skcipher request\n");
		crypto_free_skcipher(cipher->tfm);
		return -ENOMEM;
	}

	memset(cipher->iv, 0, sizeof(cipher->iv));

	init_completion(&cipher->wait.completion);

	memcpy(cipher->key, key, keylen);
	ret = crypto_skcipher_setkey(cipher->tfm, cipher->key, keylen);
	if (ret) {
		pr_err("crypto_skcipher_setkey: %d\n", ret);
		free_cipher(cipher);
		return ret;
	}

	return 0;
}

void zero_cipher_iv(struct vencrypt_cipher *cipher)
{
	memset(cipher->iv, 0, sizeof(cipher->iv));
}

void random_cipher_iv(struct vencrypt_cipher *cipher)
{
	get_random_bytes(cipher->iv, sizeof(cipher->iv)); 
}

int encrypt_block(struct vencrypt_cipher *cipher, u8 *block, const size_t block_length)
{
	int ret;

	sg_init_one(&cipher->sg, block, block_length);

	skcipher_request_set_callback(
		cipher->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &cipher->wait);

	skcipher_request_set_crypt(cipher->req, &cipher->sg, &cipher->sg, block_length,
				   cipher->iv);

	ret = crypto_wait_req(crypto_skcipher_encrypt(cipher->req), &cipher->wait);
	if (ret) {
		pr_err("encrypt_block/crypto_wait_req failed: %d\n", ret);
		return ret;
	}

	/* 
	 * CBC / IV
	 */
	memcpy(cipher->iv, block + block_length - 16, 16);
	return 0;
}

int decrypt_block(struct vencrypt_cipher *cipher, u8 *block, const size_t block_length)
{
	int ret;
	u8 next_iv[16];

	sg_init_one(&cipher->sg, block, block_length);

	skcipher_request_set_callback(
		cipher->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &cipher->wait);

	skcipher_request_set_crypt(cipher->req, &cipher->sg, &cipher->sg, block_length,
				   cipher->iv);

	memcpy(next_iv, block, 16);
	/*
	 * TODO: consider if I need to handle -EINPROGRESS, -EBUSY, -EAGAIN
	 */
	ret = crypto_wait_req(crypto_skcipher_decrypt(cipher->req), &cipher->wait);
	if (ret) {
		pr_err("decrypt_block/crypto_wait_req failed: %d\n", ret);
		return ret;
	}

	/* 
	 * CBC / IV
	 */
	memcpy(cipher->iv, next_iv, 16);
	return 0;
}

void pad_block_pkcs7(u8 *block, size_t current_size, size_t block_size)
{
	if (current_size >= block_size)
		return;

	u8 pad_value = block_size - current_size;
	pr_info("Padding block with %d \n", pad_value);
	memset(block + current_size, pad_value, pad_value);
}

size_t block_len_pkcs7(u8 *block, size_t block_size)
{
	u8 last_byte = block[block_size - 1];

	if (last_byte == 0 || last_byte > block_size)
		return block_size;

	for (size_t i = block_size - last_byte; i < block_size; i++)
		if (block[i] != last_byte)
			return block_size;

	return block_size - last_byte;
}
