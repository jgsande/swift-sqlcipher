/*
** sqlcipher_boringssl.h
**
** The BoringSSL functions SQLCipher's OpenSSL provider calls, as swift-crypto's CCryptoBoringSSL exports them:
** every name prefixed CCryptoBoringSSL_. Android and Linux compile the provider against these declarations, and
** the code comes from the consumer's link of swift-crypto's `Crypto` product, which carries CCryptoBoringSSL on
** both: this package links no BoringSSL of its own.
**
** Declared from swift-crypto 4.5.2 (BoringSSL 0226f30467f540a3f62ef48d453f93927da199b6). Check them again when
** swift-crypto's Sources/CCryptoBoringSSL/hash.txt names a new revision: a declaration that drifts from its
** definition compiles, and fails at run time.
*/
#ifndef SQLCIPHER_BORINGSSL_H
#define SQLCIPHER_BORINGSSL_H

#include <stddef.h>
#include <stdint.h>

#define OPENSSL_IS_BORINGSSL
#define OPENSSL_VERSION_NUMBER 0x1010107f
#define OPENSSL_VERSION 0

#define ERR_error_string CCryptoBoringSSL_ERR_error_string
#define ERR_get_error CCryptoBoringSSL_ERR_get_error
#define EVP_CIPHER_CTX_free CCryptoBoringSSL_EVP_CIPHER_CTX_free
#define EVP_CIPHER_CTX_new CCryptoBoringSSL_EVP_CIPHER_CTX_new
#define EVP_CIPHER_CTX_set_padding CCryptoBoringSSL_EVP_CIPHER_CTX_set_padding
#define EVP_CIPHER_block_size CCryptoBoringSSL_EVP_CIPHER_block_size
#define EVP_CIPHER_iv_length CCryptoBoringSSL_EVP_CIPHER_iv_length
#define EVP_CIPHER_key_length CCryptoBoringSSL_EVP_CIPHER_key_length
#define EVP_CIPHER_nid CCryptoBoringSSL_EVP_CIPHER_nid
#define EVP_CipherFinal_ex CCryptoBoringSSL_EVP_CipherFinal_ex
#define EVP_CipherInit_ex CCryptoBoringSSL_EVP_CipherInit_ex
#define EVP_CipherUpdate CCryptoBoringSSL_EVP_CipherUpdate
#define EVP_MD_size CCryptoBoringSSL_EVP_MD_size
#define EVP_aes_256_cbc CCryptoBoringSSL_EVP_aes_256_cbc
#define EVP_sha1 CCryptoBoringSSL_EVP_sha1
#define EVP_sha256 CCryptoBoringSSL_EVP_sha256
#define EVP_sha512 CCryptoBoringSSL_EVP_sha512
#define HMAC_CTX_free CCryptoBoringSSL_HMAC_CTX_free
#define HMAC_CTX_new CCryptoBoringSSL_HMAC_CTX_new
#define HMAC_Final CCryptoBoringSSL_HMAC_Final
#define HMAC_Init_ex CCryptoBoringSSL_HMAC_Init_ex
#define HMAC_Update CCryptoBoringSSL_HMAC_Update
#define OBJ_nid2sn CCryptoBoringSSL_OBJ_nid2sn
#define OpenSSL_version CCryptoBoringSSL_OpenSSL_version
#define PKCS5_PBKDF2_HMAC CCryptoBoringSSL_PKCS5_PBKDF2_HMAC
#define RAND_add CCryptoBoringSSL_RAND_add
#define RAND_bytes CCryptoBoringSSL_RAND_bytes

typedef struct engine_st ENGINE;
typedef struct env_md_st EVP_MD;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct hmac_ctx_st HMAC_CTX;

char *ERR_error_string(uint32_t packed_error, char *buf);
uint32_t ERR_get_error(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad);
unsigned EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
unsigned EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);
unsigned EVP_CIPHER_key_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_nid(const EVP_CIPHER *cipher);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len);
int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *engine, const uint8_t *key,
                      const uint8_t *iv, int enc);
int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len, const uint8_t *in, int in_len);
size_t EVP_MD_size(const EVP_MD *md);
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha512(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
HMAC_CTX *HMAC_CTX_new(void);
int HMAC_Final(HMAC_CTX *ctx, uint8_t *out, unsigned int *out_len);
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, size_t key_len, const EVP_MD *md, ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx, const uint8_t *data, size_t data_len);
const char *OBJ_nid2sn(int nid);
const char *OpenSSL_version(int which);
int PKCS5_PBKDF2_HMAC(const char *password, size_t password_len, const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, const EVP_MD *digest, size_t key_len, uint8_t *out_key);
void RAND_add(const void *buf, int num, double entropy);
int RAND_bytes(uint8_t *buf, size_t len);

#endif /* SQLCIPHER_BORINGSSL_H */
