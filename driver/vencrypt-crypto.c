#include <linux/random.h>
#include <linux/string.h>

#include "vencrypt-crypto.h"

void venc_free_cipher(struct venc_cipher *cipher)
{
	if (cipher->req)
		skcipher_request_free(cipher->req);
	if (cipher->tfm)
		crypto_free_skcipher(cipher->tfm);
}

int venc_init_cipher(struct venc_cipher *cipher, const u8 *key,
		     unsigned int keylen)
{
	int ret;

	cipher->tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(cipher->tfm)) {
		pr_err("%s Error allocating cipher handle: %ld\n", __func__,
		       PTR_ERR(cipher->tfm));
		return PTR_ERR(cipher->tfm);
	}

	cipher->req = skcipher_request_alloc(cipher->tfm, GFP_KERNEL);
	if (!cipher->req) {
		pr_err("%s Failed to allocate skcipher request\n", __func__);
		crypto_free_skcipher(cipher->tfm);
		return -ENOMEM;
	}

	memset(cipher->iv, 0, AES_IV_SIZE);

	init_completion(&cipher->wait.completion);

	memcpy(cipher->key, key, keylen);
	ret = crypto_skcipher_setkey(cipher->tfm, cipher->key, keylen);
	if (ret) {
		pr_err("%s crypto_skcipher_setkey: %d\n", __func__, ret);
		venc_free_cipher(cipher);
		return ret;
	}

	return 0;
}

void venc_zero_cipher_iv(struct venc_cipher *cipher)
{
	memset(cipher->iv, 0, AES_IV_SIZE);
}

void venc_random_cipher_iv(struct venc_cipher *cipher)
{
	get_random_bytes(cipher->iv, AES_IV_SIZE);
}

int venc_encrypt(struct venc_cipher *cipher, u8 *block,
		 const size_t block_length)
{
	int ret;

	sg_init_one(&cipher->sg, block, block_length);

	skcipher_request_set_callback(cipher->req,
				      CRYPTO_TFM_REQ_MAY_BACKLOG |
					      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &cipher->wait);

	skcipher_request_set_crypt(cipher->req, &cipher->sg, &cipher->sg,
				   block_length, cipher->iv);

	ret = crypto_wait_req(crypto_skcipher_encrypt(cipher->req),
			      &cipher->wait);
	if (ret) {
		pr_err("%s encrypt_block/crypto_wait_req failed: %d\n",
		       __func__, ret);
		return ret;
	}

	/* 
	 * CBC / IV
	 */
	memcpy(cipher->iv, block + block_length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
	return 0;
}

int venc_decrypt(struct venc_cipher *cipher, u8 *block,
		 const size_t block_length)
{
	int ret;
	u8 next_iv[AES_IV_SIZE];

	sg_init_one(&cipher->sg, block, block_length);

	skcipher_request_set_callback(cipher->req,
				      CRYPTO_TFM_REQ_MAY_BACKLOG |
					      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &cipher->wait);

	skcipher_request_set_crypt(cipher->req, &cipher->sg, &cipher->sg,
				   block_length, cipher->iv);

	memcpy(next_iv, block, 16);
	/*
	 * TODO: consider if I need to handle -EINPROGRESS, -EBUSY, -EAGAIN
	 */
	ret = crypto_wait_req(crypto_skcipher_decrypt(cipher->req),
			      &cipher->wait);
	if (ret) {
		pr_err("%s venc_decrypt/crypto_wait_req failed: %d\n", __func__,
		       ret);
		return ret;
	}

	/* 
	 * CBC / IV
	 */
	memcpy(cipher->iv, next_iv, AES_IV_SIZE);
	return 0;
}

void pkcs7_pad_block(u8 *block, size_t current_size, size_t block_size)
{
	if (current_size >= block_size)
		return;

	u8 pad_value = block_size - current_size;
	memset(block + current_size, pad_value, pad_value);
}

size_t pkcs7_block_len(u8 *block, size_t block_size)
{
	u8 last_byte = block[block_size - 1];

	if (last_byte == 0 || last_byte > block_size)
		return block_size;

	for (size_t i = block_size - last_byte; i < block_size; i++)
		if (block[i] != last_byte)
			return block_size;

	return block_size - last_byte;
}
