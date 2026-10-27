#include <psa/crypto.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sdcpclient.h"

#define MBEDTLS_CHK(call) if((err = (call)) != 0) { goto exit; }

static void secure_zero_memory(void* ptr, size_t len)
{
    volatile uint8_t *cursor = (volatile uint8_t *)ptr;
    while (len != 0)
    {
        *cursor = 0;
        cursor++;
        len--;
    }
}

static uint32_t big_endian32(uint32_t x)
{
    uint32_t x_be = x;
// glibc defines BIG_ENDIAN as a constant on every platform, so test the
// compiler's byte order instead. MSVC targets are little-endian.
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    x_be = (x_be & 0x0000ffff) << 16 | (x_be & 0xffff0000) >> 16;
    x_be = (x_be & 0x00ff00ff) <<  8 | (x_be & 0xff00ff00) >>  8;
#endif
    return x_be;
}

// Imports raw key material into a volatile PSA key. psa_import_key validates
// the key, so this also covers the range check for private keys and the
// on-curve check for public keys.
static int import_key(
    psa_key_type_t type, size_t bits,
    const uint8_t* data, size_t data_len,
    psa_key_usage_t usage, psa_algorithm_t alg,
    psa_key_id_t* key)
{
    int err = 0;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, type);
    psa_set_key_bits(&attributes, bits);
    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, alg);

    MBEDTLS_CHK(psa_crypto_init());
    MBEDTLS_CHK(psa_import_key(&attributes, data, data_len, key));

exit:
    psa_reset_key_attributes(&attributes);

    return err;
}

static int import_hmac_key(const uint8_t* data, size_t data_len, psa_key_id_t* key)
{
    return import_key(
        PSA_KEY_TYPE_HMAC,
        data_len * CHAR_BIT,
        data, data_len,
        PSA_KEY_USAGE_SIGN_MESSAGE, PSA_ALG_HMAC(PSA_ALG_SHA_256),
        key);
}

int sdcpcli_gen_rand(uint8_t* rand, size_t rand_len)
{
    if (rand == NULL || rand_len == 0)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;

    MBEDTLS_CHK(psa_crypto_init());
    MBEDTLS_CHK(psa_generate_random(rand, rand_len));

exit:
    return err;
}

int sdcpcli_kdf(
    const uint8_t* key, size_t key_len,
    const char* label,
    const uint8_t* context, size_t context_len,
    uint8_t* output, size_t output_len)
{
    if (key == NULL || key_len < SDCP_DIGEST_SIZE_V1 ||
        label == NULL ||
        (context == NULL && context_len > 0) ||
        output == NULL || output_len > UINT32_MAX / CHAR_BIT)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;
    size_t olen = 0;
    const psa_algorithm_t alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);
    const uint32_t n = (uint32_t)((output_len + SDCP_DIGEST_SIZE_V1 - 1) / SDCP_DIGEST_SIZE_V1);
    const uint32_t l_bits_be = big_endian32((uint32_t)output_len * 8);

    psa_key_id_t hmac_key = PSA_KEY_ID_NULL;
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    uint8_t tmp[SDCP_DIGEST_SIZE_V1] = { 0 };

    MBEDTLS_CHK(import_hmac_key(key, key_len, &hmac_key));
    for (uint32_t i = 0; i < n; ++i)
    {
        uint32_t i_be = big_endian32(i + 1);
        size_t offset = i * SDCP_DIGEST_SIZE_V1;
        size_t bytes_remaining = output_len - offset;

        // i_be || label || context || l_bits_be
        MBEDTLS_CHK(psa_mac_sign_setup(&op, hmac_key, alg));
        MBEDTLS_CHK(psa_mac_update(&op, (uint8_t*)&i_be, sizeof(i_be)));
        MBEDTLS_CHK(psa_mac_update(&op, (uint8_t*)label, strlen(label) + 1));
        if (context_len > 0)
        {
            MBEDTLS_CHK(psa_mac_update(&op, context, context_len));
        }
        MBEDTLS_CHK(psa_mac_update(&op, (uint8_t*)&l_bits_be, sizeof(l_bits_be)));

        MBEDTLS_CHK(psa_mac_sign_finish(&op, tmp, sizeof(tmp), &olen));

        memcpy(output + offset, tmp, bytes_remaining < 32 ? bytes_remaining : 32);
    }

exit:
    psa_mac_abort(&op);
    psa_destroy_key(hmac_key);
    secure_zero_memory(tmp, sizeof(tmp));

    return err;
}

int sdcpcli_keygen(sdcp_keypair* keypair)
{
    if (keypair == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;
    size_t olen = 0;

    psa_key_id_t key = PSA_KEY_ID_NULL;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, SDCP_PRIVATE_KEY_SIZE_V1 * CHAR_BIT);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);

    MBEDTLS_CHK(psa_crypto_init());
    MBEDTLS_CHK(psa_generate_key(&attributes, &key));

    // 0x04||x||y
    MBEDTLS_CHK(psa_export_public_key(key, keypair->pk, sizeof(keypair->pk), &olen));
    assert(olen == sizeof(keypair->pk));

    MBEDTLS_CHK(psa_export_key(key, keypair->sk, sizeof(keypair->sk), &olen));
    assert(olen == sizeof(keypair->sk));

exit:
    psa_destroy_key(key);
    psa_reset_key_attributes(&attributes);

    return err;
}

int sdcpcli_hash(const uint8_t* data, size_t len, uint8_t* hash, size_t hash_len)
{
    if (data == NULL || len == 0 || hash == NULL || hash_len < SDCP_DIGEST_SIZE_V1)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;
    size_t olen = 0;

    MBEDTLS_CHK(psa_crypto_init());
    MBEDTLS_CHK(psa_hash_compute(PSA_ALG_SHA_256, data, len, hash, hash_len, &olen));

exit:
    return err;
}

int sdcpcli_sign_hash(
    const uint8_t* sk, size_t sk_len,
    const uint8_t* hash, size_t hash_len,
    sdcp_signature* signature)
{
    if (sk == NULL || sk_len < SDCP_PRIVATE_KEY_SIZE_V1 ||
        hash == NULL || hash_len < SDCP_DIGEST_SIZE_V1 ||
        signature == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;
    size_t olen = 0;
    const psa_algorithm_t alg = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);

    psa_key_id_t key = PSA_KEY_ID_NULL;

    // r||s
    uint8_t sig[SDCP_SIGNATURE_SIZE_V1] = { 0 };

    MBEDTLS_CHK(import_key(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
        SDCP_PRIVATE_KEY_SIZE_V1 * CHAR_BIT,
        sk, SDCP_PRIVATE_KEY_SIZE_V1,
        PSA_KEY_USAGE_SIGN_HASH, alg,
        &key));

    MBEDTLS_CHK(psa_sign_hash(
        key, alg,
        hash, SDCP_DIGEST_SIZE_V1,
        sig, sizeof(sig), &olen));
    assert(olen == sizeof(sig));

    memcpy(signature->r, sig, sizeof(signature->r));
    memcpy(signature->s, sig + sizeof(signature->r), sizeof(signature->s));

exit:
    psa_destroy_key(key);

    return err;
}

int sdcpcli_verify(
    const uint8_t* pk, size_t pk_len,
    const uint8_t* hash, size_t hash_len,
    const sdcp_signature* signature)
{
    if (pk == NULL || pk_len < SDCP_PUBLIC_KEY_SIZE_V1 ||
        hash == NULL || hash_len < SDCP_DIGEST_SIZE_V1 ||
        signature == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;
    const psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);

    psa_key_id_t key = PSA_KEY_ID_NULL;

    // r||s
    uint8_t sig[SDCP_SIGNATURE_SIZE_V1] = { 0 };
    memcpy(sig, signature->r, sizeof(signature->r));
    memcpy(sig + sizeof(signature->r), signature->s, sizeof(signature->s));

    MBEDTLS_CHK(import_key(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1),
        SDCP_PRIVATE_KEY_SIZE_V1 * CHAR_BIT,
        pk, pk_len,
        PSA_KEY_USAGE_VERIFY_HASH, alg,
        &key));

    // ECDSA only uses the leftmost bits of the hash up to the size of the
    // group order, so longer hashes are truncated as before.
    MBEDTLS_CHK(psa_verify_hash(
        key, alg,
        hash, SDCP_DIGEST_SIZE_V1,
        sig, sizeof(sig)));

exit:
    psa_destroy_key(key);

    return err;
}

int sdcpcli_secret_agreement(
    const uint8_t* pk, size_t pk_len,
    const uint8_t* sk, size_t sk_len,
    uint8_t* secret, size_t secret_len)
{
    if (pk == NULL || pk_len < SDCP_PUBLIC_KEY_SIZE_V1 ||
        sk == NULL || sk_len < SDCP_PRIVATE_KEY_SIZE_V1 ||
        secret == NULL || secret_len < SDCP_CURVE_FIELD_SIZE_V1)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;
    size_t olen = 0;

    psa_key_id_t key = PSA_KEY_ID_NULL;

    MBEDTLS_CHK(import_key(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
        SDCP_PRIVATE_KEY_SIZE_V1 * CHAR_BIT,
        sk, SDCP_PRIVATE_KEY_SIZE_V1,
        PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH,
        &key));

    // The shared secret is the big-endian x-coordinate of the shared point.
    MBEDTLS_CHK(psa_raw_key_agreement(
        PSA_ALG_ECDH, key,
        pk, SDCP_PUBLIC_KEY_SIZE_V1,
        secret, SDCP_CURVE_FIELD_SIZE_V1, &olen));
    assert(olen == SDCP_CURVE_FIELD_SIZE_V1);

exit:
    psa_destroy_key(key);

    return err;
}

int sdcpcli_derive_master_secret(
    const uint8_t* pk, size_t pk_len,
    const uint8_t* sk, size_t sk_len,
    const uint8_t* rh, size_t rh_len,
    const uint8_t* rd, size_t rd_len,
    uint8_t* ms, size_t ms_len)
{
    if (rh == NULL || rh_len < SDCP_RANDOM_SIZE_V1 ||
        rd == NULL || rd_len < SDCP_RANDOM_SIZE_V1)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;

    uint8_t r[SDCP_RANDOM_SIZE_V1 * 2] = { 0 };
    memcpy(r, rh, SDCP_RANDOM_SIZE_V1);
    memcpy(r + SDCP_RANDOM_SIZE_V1, rd, SDCP_RANDOM_SIZE_V1);

    uint8_t pms[SDCP_CURVE_FIELD_SIZE_V1] = { 0 };
    MBEDTLS_CHK(sdcpcli_secret_agreement(
        pk, pk_len,
        sk, sk_len,
        pms, sizeof(pms)));

    MBEDTLS_CHK(sdcpcli_kdf(
        pms, sizeof(pms),
        SDCP_LABEL_MASTER_SECRET,
        r, sizeof(r),
        ms, ms_len));

exit:
    secure_zero_memory(r, sizeof(r));
    secure_zero_memory(pms, sizeof(pms));

    return err;
}

int sdcpcli_derive_application_keys(
    const uint8_t* ms, size_t ms_len,
    sdcp_application_keys* keys)
{
    return sdcpcli_kdf(
        ms, ms_len,
        SDCP_LABEL_APPLICATION_KEYS,
        NULL, 0,
        (uint8_t*)keys, sizeof(*keys));
}

int sdcpcli_sign_firmware(
    const uint8_t* skd, size_t skd_len,
    const uint8_t* fw, size_t fw_len,
    sdcp_keypair* fw_keypair,
    sdcp_firmware_signature* fw_sig)
{
    if (fw == NULL || fw_len == 0 || fw_sig == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;
    size_t olen = 0;

    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;

    uint8_t md[SDCP_DIGEST_SIZE_V1] = { 0 };

    // Two-byte {0xC0, 0x01} header
    const uint8_t header[2] = {
        (uint8_t)(SDCP_DEVICE_SIGNATURE_HEADER_V1 >> 8),
        (uint8_t)(SDCP_DEVICE_SIGNATURE_HEADER_V1 & 0xff)
    };

    MBEDTLS_CHK(sdcpcli_keygen(fw_keypair));

    MBEDTLS_CHK(psa_hash_setup(&op, PSA_ALG_SHA_256));
    MBEDTLS_CHK(psa_hash_update(&op, fw, fw_len));
    MBEDTLS_CHK(psa_hash_finish(&op, fw_sig->hash, sizeof(fw_sig->hash), &olen));

    MBEDTLS_CHK(psa_hash_setup(&op, PSA_ALG_SHA_256));
    MBEDTLS_CHK(psa_hash_update(&op, header, sizeof(header)));
    MBEDTLS_CHK(psa_hash_update(&op, fw_sig->hash, sizeof(fw_sig->hash)));
    MBEDTLS_CHK(psa_hash_update(&op, fw_keypair->pk, sizeof(fw_keypair->pk)));
    MBEDTLS_CHK(psa_hash_finish(&op, md, sizeof(md), &olen));

    // Sig(sk_d, H(C001||H(fw)||pk_f))
    MBEDTLS_CHK(sdcpcli_sign_hash(skd, skd_len, md, sizeof(md), &fw_sig->sig));

exit:
    psa_hash_abort(&op);

    return err;
}

int sdcpcli_hash_claim(
    const uint8_t* cert, size_t cert_len,
    const uint8_t* pkd, size_t pkd_len,
    const uint8_t* pkf, size_t pkf_len,
    const sdcp_firmware_signature* sd,
    const sdcp_signature* sm,
    uint8_t* hash, size_t hash_len)
{
    if (cert == NULL || cert_len == 0 ||
        pkd == NULL || pkd_len < SDCP_PUBLIC_KEY_SIZE_V1 ||
        pkf == NULL || pkf_len < SDCP_PUBLIC_KEY_SIZE_V1 ||
        sd == NULL || sm == NULL ||
        hash == NULL || hash_len < SDCP_DIGEST_SIZE_V1)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;
    size_t olen = 0;

    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;

    MBEDTLS_CHK(psa_crypto_init());

    // c <- (cert_m, pk_d, pk_f, h_f, s_m, s_d)
    MBEDTLS_CHK(psa_hash_setup(&op, PSA_ALG_SHA_256));
    MBEDTLS_CHK(psa_hash_update(&op, cert, cert_len));
    MBEDTLS_CHK(psa_hash_update(&op, pkd, SDCP_PUBLIC_KEY_SIZE_V1));
    MBEDTLS_CHK(psa_hash_update(&op, pkf, SDCP_PUBLIC_KEY_SIZE_V1));
    MBEDTLS_CHK(psa_hash_update(&op, sd->hash, sizeof(sd->hash)));
    MBEDTLS_CHK(psa_hash_update(&op, (const uint8_t*)sm, sizeof(*sm)));
    MBEDTLS_CHK(psa_hash_update(&op, (const uint8_t*)&sd->sig, sizeof(sd->sig)));
    MBEDTLS_CHK(psa_hash_finish(&op, hash, hash_len, &olen));

exit:
    psa_hash_abort(&op);

    return err;

}

typedef struct { const uint8_t* ptr; size_t len; } mac_data;

static int mac_with_label(
    const sdcp_application_keys* keys,
    const char* label,
    const mac_data* data, size_t count,
    uint8_t* mac, size_t mac_len)
{
    if (keys == NULL || label == NULL ||
        (data == NULL && count > 0) ||
        mac == NULL || mac_len < SDCP_DIGEST_SIZE_V1)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;
    size_t olen = 0;

    psa_key_id_t hmac_key = PSA_KEY_ID_NULL;
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;

    MBEDTLS_CHK(import_hmac_key(keys->s, sizeof(keys->s), &hmac_key));

    MBEDTLS_CHK(psa_mac_sign_setup(&op, hmac_key, PSA_ALG_HMAC(PSA_ALG_SHA_256)));
    MBEDTLS_CHK(psa_mac_update(&op, (const uint8_t*)label, strlen(label) + 1));
    for (size_t i = 0; i < count; ++i)
    {
        MBEDTLS_CHK(psa_mac_update(&op, data[i].ptr, data[i].len));
    }
    MBEDTLS_CHK(psa_mac_sign_finish(&op, mac, mac_len, &olen));

exit:
    psa_mac_abort(&op);
    psa_destroy_key(hmac_key);

    return err;
}

int sdcpcli_mac_claim_hash(
    const sdcp_application_keys* keys,
    const uint8_t* hash, size_t hash_len,
    uint8_t* mac, size_t mac_len)
{
    if (hash == NULL || hash_len < SDCP_DIGEST_SIZE_V1)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    mac_data data[1] = { 0 };
    data[0].ptr = hash;
    data[0].len = SDCP_DIGEST_SIZE_V1;

    return mac_with_label(
        keys,
        SDCP_LABEL_CONNECT,
        data, sizeof(data) / sizeof(data[0]),
        mac, mac_len);
}

int sdcpcli_mac_reconnect(
    const sdcp_application_keys* keys,
    const uint8_t* rand, size_t rand_len,
    uint8_t* mac, size_t mac_len)
{
    if (rand == NULL || rand_len < SDCP_RANDOM_SIZE_V1)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    mac_data data[1] = { 0 };
    data[0].ptr = rand;
    data[0].len = SDCP_RANDOM_SIZE_V1;

    return mac_with_label(
        keys,
        SDCP_LABEL_RECONNECT,
        data, sizeof(data) / sizeof(data[0]),
        mac, mac_len);
}

int sdcpcli_mac_encrypted_sample(
    const sdcp_application_keys* keys,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* enc, size_t enc_len,
    uint8_t* mac, size_t mac_len)
{
    if (nonce == NULL || nonce_len == 0 ||
        iv == NULL || iv_len < SDCP_ENCRYPTION_BLOCK_SIZE_V1 ||
        enc == NULL || enc_len == 0)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    mac_data data[3] = { 0 };
    data[0].ptr = nonce;
    data[0].len = nonce_len;
    data[1].ptr = iv;
    data[1].len = SDCP_ENCRYPTION_BLOCK_SIZE_V1;
    data[2].ptr = enc;
    data[2].len = enc_len;

    return mac_with_label(
        keys,
        SDCP_LABEL_SAMPLE,
        data, sizeof(data) / sizeof(data[0]),
        mac, mac_len);
}

int sdcpcli_mac_identity(
    const sdcp_application_keys* keys,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* id, size_t id_len,
    uint8_t* mac, size_t mac_len)
{
    if (nonce == NULL || nonce_len == 0 ||
        id == NULL || id_len == 0)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    mac_data data[2] = { 0 };
    data[0].ptr = nonce;
    data[0].len = nonce_len;
    data[1].ptr = id;
    data[1].len = id_len;

    return mac_with_label(
        keys,
        SDCP_LABEL_IDENTIFY,
        data, sizeof(data) / sizeof(data[0]),
        mac, mac_len);
}

int sdcpcli_verify_enrollment_mac(
    const sdcp_application_keys* keys,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* mac, size_t mac_len)
{
    if (nonce == NULL || nonce_len == 0 ||
        mac == NULL || mac_len < SDCP_DIGEST_SIZE_V1)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    mac_data data[1] = { 0 };
    data[0].ptr = nonce;
    data[0].len = nonce_len;

    // A failed HMAC leaves verify_mac zeroed, so the comparison below would
    // accept an all-zero MAC.
    uint8_t verify_mac[SDCP_DIGEST_SIZE_V1] = { 0 };
    int err = mac_with_label(
        keys,
        SDCP_LABEL_ENROLL,
        data, sizeof(data) / sizeof(data[0]),
        verify_mac, sizeof(verify_mac));
    if (err != 0)
    {
        return err;
    }

    int diff = 0;
    for (size_t i = 0; i < sizeof(verify_mac); i++)
    {
        diff |= mac[i] ^ verify_mac[i];
    }

    return diff == 0 ? 0 : PSA_ERROR_INVALID_ARGUMENT;
}

static int generate_iv(
    const sdcp_application_keys* keys,
    uint32_t* iv_seed,
    uint8_t* iv, size_t iv_len)
{
    if (keys == NULL || iv_seed == NULL ||
        iv == NULL || iv_len < SDCP_ENCRYPTION_BLOCK_SIZE_V1)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    int err = 0;
    const char iv_label[] = "iv";
    // Advance the caller's counter so that every sample gets a fresh IV.
    uint32_t seed = big_endian32((*iv_seed)++);
    size_t olen = 0;

    psa_key_id_t hmac_key = PSA_KEY_ID_NULL;
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    uint8_t mac[SDCP_DIGEST_SIZE_V1] = { 0 };

    MBEDTLS_CHK(import_hmac_key(keys->s, sizeof(keys->s), &hmac_key));

    MBEDTLS_CHK(psa_mac_sign_setup(&op, hmac_key, PSA_ALG_HMAC(PSA_ALG_SHA_256)));
    MBEDTLS_CHK(psa_mac_update(&op, (const uint8_t*)iv_label, strlen(iv_label) + 1));
    MBEDTLS_CHK(psa_mac_update(&op, (const uint8_t*)&seed, sizeof(seed)));
    MBEDTLS_CHK(psa_mac_sign_finish(&op, mac, sizeof(mac), &olen));

    // The IV is the leading block of the HMAC output.
    memcpy(iv, mac, SDCP_ENCRYPTION_BLOCK_SIZE_V1);

exit:
    psa_mac_abort(&op);
    psa_destroy_key(hmac_key);

    return err;
}

int sdcpcli_encrypt_sample(
    const sdcp_application_keys* keys,
    uint32_t* iv_seed,
    const uint8_t* sample, size_t sample_len,
    uint8_t* iv, size_t iv_len,
    uint8_t* enc, size_t enc_len, size_t* enc_olen)
{
    if (keys == NULL || iv_seed == NULL ||
        sample == NULL || sample_len == 0 ||
        iv == NULL || iv_len < SDCP_ENCRYPTION_BLOCK_SIZE_V1 ||
        enc == NULL || enc_olen == NULL)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (enc_len < sample_len + SDCP_ENCRYPTION_BLOCK_SIZE_V1)
    {
        *enc_olen = sample_len + SDCP_ENCRYPTION_BLOCK_SIZE_V1;
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    int err = 0;
    size_t update_len = 0;
    size_t finish_len = 0;
    // AES-256-CBC with PKCS#7 padding, the mbedtls 2.x cipher module default.
    const psa_algorithm_t alg = PSA_ALG_CBC_PKCS7;

    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;

    MBEDTLS_CHK(import_key(
        PSA_KEY_TYPE_AES,
        sizeof(keys->k) * CHAR_BIT,
        keys->k, sizeof(keys->k),
        PSA_KEY_USAGE_ENCRYPT, alg,
        &key));

    MBEDTLS_CHK(generate_iv(keys, iv_seed, iv, iv_len));

    MBEDTLS_CHK(psa_cipher_encrypt_setup(&op, key, alg));
    MBEDTLS_CHK(psa_cipher_set_iv(&op, iv, SDCP_ENCRYPTION_BLOCK_SIZE_V1));
    MBEDTLS_CHK(psa_cipher_update(
        &op,
        sample, sample_len,
        enc, enc_len, &update_len));
    MBEDTLS_CHK(psa_cipher_finish(
        &op,
        enc + update_len, enc_len - update_len, &finish_len));

    *enc_olen = update_len + finish_len;

exit:
    psa_cipher_abort(&op);
    psa_destroy_key(key);

    return err;
}
