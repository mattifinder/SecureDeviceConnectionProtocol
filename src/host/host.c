#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "host.h"
#include "modelcerts.h"
#include "sdcpclient.h"

static const char session_magic[8] = { 'S', 'D', 'C', 'P', 'S', 'E', 'S', '1' };

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

static int ct_equal(const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
    {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

void sdcp_print_bytes(FILE* out, const char* label, const uint8_t* bytes, size_t len)
{
    const size_t bytes_per_line = 32;

    fprintf(out, "%s:", label);
    for (size_t i = 0; i < len; ++i)
    {
        if ((i % bytes_per_line) == 0)
        {
            fprintf(out, "\n  ");
        }
        fprintf(out, "%02x", bytes[i]);
    }
    fputc('\n', out);
}

const char* sdcp_host_result_str(sdcp_host_result r)
{
    switch (r)
    {
    case SDCP_HOST_OK: return "ok";
    case SDCP_HOST_ERR_TRANSPORT: return "transport error";
    case SDCP_HOST_ERR_VERIFY: return "verification failed";
    case SDCP_HOST_ERR_CRYPTO: return "crypto error";
    case SDCP_HOST_ERR_NO_SESSION: return "no session; connect first";
    case SDCP_HOST_NO_MATCH: return "no match";
    }
    return "unknown error";
}

// WINBIO_BIOMETRIC_SUBTYPE values for fingerprints (ANSI 381 positions).
static const char* sub_factor_str(uint8_t sub_factor)
{
    static const char* fingers[] = {
        "unknown", "right thumb", "right index", "right middle", "right ring", "right little",
        "left thumb", "left index", "left middle", "left ring", "left little"
    };
    if (sub_factor < sizeof(fingers) / sizeof(fingers[0]))
    {
        return fingers[sub_factor];
    }
    return sub_factor == 0xff ? "any" : "unknown";
}

// WINBIO_REJECT_DETAIL values for fingerprints.
static const char* reject_detail_str(uint32_t detail)
{
    static const char* details[] = {
        "none", "too high", "too low", "too left", "too right", "too fast",
        "too slow", "poor quality", "too skewed", "too short", "merge failure"
    };
    if (detail < sizeof(details) / sizeof(details[0]))
    {
        return details[detail];
    }
    return "unknown";
}

// Returns the accepted chain whose leaf is cert_m, or NULL. Like the Windows
// adapter, the leaf must match byte for byte.
static const sdcp_model_chain* find_model_chain(
    const sdcp_connect_response* data,
    const sdcp_host_options* opt)
{
    for (size_t i = 0; i < g_sdcp_model_chain_count; i++)
    {
        const sdcp_model_chain* chain = &g_sdcp_model_chains[i];
        if (chain->legacy && !opt->allow_legacy_model)
        {
            continue;
        }
        if (chain->leaf_len == data->cert_len &&
            memcmp(chain->leaf, data->cert, chain->leaf_len) == 0)
        {
            return chain;
        }
    }
    return NULL;
}

// Extracts pk_m from cert_m. The certificate must be one the Windows adapter
// accepts unless any_model_cert is set; with ca_path its chain is validated,
// using the intermediates from modelcerts.c for a pinned leaf.
static sdcp_host_result model_key_from_cert(
    const sdcp_connect_response* data,
    const sdcp_host_options* opt,
    uint8_t pk_m[SDCP_PUBLIC_KEY_SIZE_V1])
{
    if (data->cert_len == SDCP_PUBLIC_KEY_SIZE_V1 &&
        data->cert[0] == SEC1_UNCOMPRESSED_POINT_HEADER)
    {
        if (!opt->allow_raw_model_key)
        {
            fprintf(opt->log, "error: device sent a raw public key instead of a model certificate\n");
            return SDCP_HOST_ERR_VERIFY;
        }
        fprintf(opt->log, "warning: model certificate is a raw public key; not validated\n");
        memcpy(pk_m, data->cert, SDCP_PUBLIC_KEY_SIZE_V1);
        return SDCP_HOST_OK;
    }

    sdcp_host_result result = SDCP_HOST_ERR_VERIFY;
    size_t olen = 0;
    char name[256] = { 0 };

    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    mbedtls_x509_crt trusted;
    mbedtls_x509_crt_init(&trusted);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;

    const sdcp_model_chain* pinned = find_model_chain(data, opt);
    if (pinned != NULL)
    {
        fprintf(opt->log, "model certificate: %s, accepted by the Windows adapter\n", pinned->name);
    }
    else if (opt->any_model_cert)
    {
        fprintf(opt->log, "warning: model certificate is not one the Windows adapter accepts\n");
    }
    else
    {
        fprintf(opt->log, "FAIL: model certificate is not one the Windows adapter accepts (see --any-model-cert)\n");
        goto exit;
    }

    if (mbedtls_x509_crt_parse_der(&chain, data->cert, data->cert_len) != 0)
    {
        fprintf(opt->log, "error: model certificate is not valid DER X.509\n");
        goto exit;
    }

    if (mbedtls_x509_dn_gets(name, sizeof(name), &chain.subject) > 0)
    {
        fprintf(opt->log, "model certificate subject: %s\n", name);
    }

    if (opt->ca_path != NULL)
    {
        uint32_t flags = 0;

        // The device sends only the leaf. For a pinned leaf, add the
        // intermediates the adapter would; otherwise they must be in ca_path.
        if (pinned != NULL &&
            (mbedtls_x509_crt_parse_der(&chain, pinned->ca1, pinned->ca1_len) != 0 ||
             mbedtls_x509_crt_parse_der(&chain, pinned->ca2, pinned->ca2_len) != 0))
        {
            fprintf(opt->log, "error: could not parse the built-in intermediate certificates\n");
            goto exit;
        }

        if (mbedtls_x509_crt_parse_file(&trusted, opt->ca_path) < 0)
        {
            fprintf(opt->log, "error: could not load trusted roots from %s\n", opt->ca_path);
            goto exit;
        }

        const uint32_t validity = MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE;
        if (mbedtls_x509_crt_verify(&chain, &trusted, NULL, NULL, &flags, NULL, NULL) != 0)
        {
            char info[512] = { 0 };
            mbedtls_x509_crt_verify_info(info, sizeof(info), "  ", flags);
            if (opt->strict_validity || (flags & ~validity) != 0)
            {
                fprintf(opt->log, "FAIL: model certificate chain is not trusted:\n%s", info);
                goto exit;
            }
            fprintf(opt->log, "warning: model certificate chain is trusted but outside its validity period"
                " (ignored, as on Windows; see --strict-validity):\n%s", info);
        }
        fprintf(opt->log, "ok: model certificate chain\n");
    }
    else if (pinned == NULL)
    {
        fprintf(opt->log, "warning: no --ca given; model certificate chain not validated\n");
    }

    if (mbedtls_pk_get_psa_attributes(&chain.pk, PSA_KEY_USAGE_VERIFY_HASH, &attributes) != 0 ||
        psa_get_key_type(&attributes) != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1) ||
        psa_get_key_bits(&attributes) != SDCP_PRIVATE_KEY_SIZE_V1 * 8)
    {
        fprintf(opt->log, "error: model certificate key is not a P-256 public key\n");
        goto exit;
    }

    if (mbedtls_pk_import_into_psa(&chain.pk, &attributes, &key) != 0 ||
        psa_export_public_key(key, pk_m, SDCP_PUBLIC_KEY_SIZE_V1, &olen) != PSA_SUCCESS ||
        olen != SDCP_PUBLIC_KEY_SIZE_V1)
    {
        fprintf(opt->log, "error: could not extract the model public key\n");
        result = SDCP_HOST_ERR_CRYPTO;
        goto exit;
    }

    result = SDCP_HOST_OK;

exit:
    psa_destroy_key(key);
    psa_reset_key_attributes(&attributes);
    mbedtls_x509_crt_free(&trusted);
    mbedtls_x509_crt_free(&chain);

    return result;
}

sdcp_host_result sdcp_host_connect(
    sdcp_transport* t,
    const sdcp_host_options* opt,
    sdcp_session* session)
{
    sdcp_host_result result = SDCP_HOST_ERR_CRYPTO;
    FILE* log = opt->log;

    uint8_t r_h[SDCP_RANDOM_SIZE_V1] = { 0 };
    sdcp_keypair host_key = { 0 };
    uint8_t ms[SDCP_DIGEST_SIZE_V1] = { 0 };
    sdcp_application_keys keys = { 0 };
    sdcp_connect_response data;

    memset(session, 0, sizeof(*session));

    if (sdcpcli_gen_rand(r_h, sizeof(r_h)) != 0 || sdcpcli_keygen(&host_key) != 0)
    {
        goto exit;
    }

    if (t->connect(t, r_h, host_key.pk, &data) != 0)
    {
        result = SDCP_HOST_ERR_TRANSPORT;
        goto exit;
    }

    sdcp_print_bytes(log, "pk_d", data.pk_d, SDCP_PUBLIC_KEY_SIZE_V1);
    sdcp_print_bytes(log, "pk_f", data.pk_f, SDCP_PUBLIC_KEY_SIZE_V1);
    sdcp_print_bytes(log, "h_f", data.h_f, SDCP_DIGEST_SIZE_V1);

    // The Windows adapter checks the model certificate before anything else.
    uint8_t pk_m[SDCP_PUBLIC_KEY_SIZE_V1] = { 0 };
    if ((result = model_key_from_cert(&data, opt, pk_m)) != SDCP_HOST_OK)
    {
        goto exit;
    }

    // ms <- KDF(ECDH(sk_h, pk_f), "master secret", r_h||r_d)
    // (s, k) <- KDF(ms, "application keys")
    result = SDCP_HOST_ERR_CRYPTO;
    if (sdcpcli_derive_master_secret(
            data.pk_f, SDCP_PUBLIC_KEY_SIZE_V1,
            host_key.sk, sizeof(host_key.sk),
            r_h, sizeof(r_h),
            data.device_random, SDCP_RANDOM_SIZE_V1,
            ms, sizeof(ms)) != 0 ||
        sdcpcli_derive_application_keys(ms, sizeof(ms), &keys) != 0)
    {
        fprintf(log, "error: key agreement with pk_f failed\n");
        goto exit;
    }

    // m == MAC(s, "connect"||H(c))
    sdcp_firmware_signature sd;
    sdcp_signature sm;
    memcpy(sd.hash, data.h_f, sizeof(sd.hash));
    memcpy(&sd.sig, data.s_d, sizeof(sd.sig));
    memcpy(&sm, data.s_m, sizeof(sm));

    uint8_t claim_hash[SDCP_DIGEST_SIZE_V1] = { 0 };
    uint8_t mac[SDCP_DIGEST_SIZE_V1] = { 0 };
    if (sdcpcli_hash_claim(
            data.cert, data.cert_len,
            data.pk_d, SDCP_PUBLIC_KEY_SIZE_V1,
            data.pk_f, SDCP_PUBLIC_KEY_SIZE_V1,
            &sd, &sm,
            claim_hash, sizeof(claim_hash)) != 0 ||
        sdcpcli_mac_claim_hash(&keys, claim_hash, sizeof(claim_hash), mac, sizeof(mac)) != 0)
    {
        goto exit;
    }

    result = SDCP_HOST_ERR_VERIFY;
    if (!ct_equal(mac, data.mac, sizeof(mac)))
    {
        fprintf(log, "FAIL: claim MAC\n");
        goto exit;
    }
    fprintf(log, "ok: claim MAC\n");

    // Verify(pk_m, H(pk_d), s_m)
    uint8_t hash[SDCP_DIGEST_SIZE_V1] = { 0 };
    result = SDCP_HOST_ERR_VERIFY;
    if (sdcpcli_hash(data.pk_d, SDCP_PUBLIC_KEY_SIZE_V1, hash, sizeof(hash)) != 0 ||
        sdcpcli_verify(pk_m, sizeof(pk_m), hash, sizeof(hash), &sm) != 0)
    {
        fprintf(log, "FAIL: model signature over pk_d\n");
        goto exit;
    }
    fprintf(log, "ok: model signature over pk_d\n");

    // Verify(pk_d, H(C001||h_f||pk_f), s_d)
    uint8_t signed_data[2 + SDCP_DIGEST_SIZE_V1 + SDCP_PUBLIC_KEY_SIZE_V1];
    signed_data[0] = (uint8_t)(SDCP_DEVICE_SIGNATURE_HEADER_V1 >> 8);
    signed_data[1] = (uint8_t)(SDCP_DEVICE_SIGNATURE_HEADER_V1 & 0xff);
    memcpy(signed_data + 2, data.h_f, SDCP_DIGEST_SIZE_V1);
    memcpy(signed_data + 2 + SDCP_DIGEST_SIZE_V1, data.pk_f, SDCP_PUBLIC_KEY_SIZE_V1);

    if (sdcpcli_hash(signed_data, sizeof(signed_data), hash, sizeof(hash)) != 0 ||
        sdcpcli_verify(data.pk_d, SDCP_PUBLIC_KEY_SIZE_V1, hash, sizeof(hash), &sd.sig) != 0)
    {
        fprintf(log, "FAIL: device signature over firmware\n");
        goto exit;
    }
    fprintf(log, "ok: device signature over firmware\n");

    if (opt->expected_h_f != NULL)
    {
        if (!ct_equal(opt->expected_h_f, data.h_f, SDCP_DIGEST_SIZE_V1))
        {
            fprintf(log, "FAIL: firmware hash does not match the expected value\n");
            goto exit;
        }
        fprintf(log, "ok: firmware hash matches\n");
    }
    else
    {
        fprintf(log, "warning: no --expect-fw-hash given; firmware hash not checked\n");
    }

    session->established = 1;
    session->keys = keys;
    memcpy(session->pk_d, data.pk_d, sizeof(session->pk_d));
    memcpy(session->h_f, data.h_f, sizeof(session->h_f));
    result = SDCP_HOST_OK;

exit:
    secure_zero_memory(&host_key, sizeof(host_key));
    secure_zero_memory(ms, sizeof(ms));
    secure_zero_memory(&keys, sizeof(keys));

    return result;
}

sdcp_host_result sdcp_host_reconnect(
    sdcp_transport* t,
    const sdcp_host_options* opt,
    const sdcp_session* session)
{
    if (session == NULL || !session->established)
    {
        return SDCP_HOST_ERR_NO_SESSION;
    }

    uint8_t r_h[SDCP_RANDOM_SIZE_V1] = { 0 };
    uint8_t mac[SDCP_DIGEST_SIZE_V1] = { 0 };
    uint8_t expected[SDCP_DIGEST_SIZE_V1] = { 0 };

    if (sdcpcli_gen_rand(r_h, sizeof(r_h)) != 0)
    {
        return SDCP_HOST_ERR_CRYPTO;
    }

    if (t->reconnect(t, r_h, mac) != 0)
    {
        return SDCP_HOST_ERR_TRANSPORT;
    }

    // m == MAC(s, "reconnect"||r_h)
    if (sdcpcli_mac_reconnect(&session->keys, r_h, sizeof(r_h), expected, sizeof(expected)) != 0)
    {
        return SDCP_HOST_ERR_CRYPTO;
    }

    if (!ct_equal(mac, expected, sizeof(mac)))
    {
        fprintf(opt->log, "FAIL: reconnect MAC\n");
        return SDCP_HOST_ERR_VERIFY;
    }
    fprintf(opt->log, "ok: reconnect MAC\n");

    return SDCP_HOST_OK;
}

sdcp_host_result sdcp_host_identify(
    sdcp_transport* t,
    const sdcp_host_options* opt,
    const sdcp_session* session,
    sdcp_identity* identity)
{
    if (session == NULL || !session->established)
    {
        return SDCP_HOST_ERR_NO_SESSION;
    }

    uint8_t nonce[SDCP_RANDOM_SIZE_V1] = { 0 };
    uint8_t expected[SDCP_DIGEST_SIZE_V1] = { 0 };

    if (sdcpcli_gen_rand(nonce, sizeof(nonce)) != 0)
    {
        return SDCP_HOST_ERR_CRYPTO;
    }

    memset(identity, 0, sizeof(*identity));
    if (t->identify(t, nonce, sizeof(nonce), identity) != 0)
    {
        return SDCP_HOST_ERR_TRANSPORT;
    }

    if (!identity->matched)
    {
        if (identity->reject_detail != 0)
        {
            fprintf(opt->log, "capture rejected: %s\n", reject_detail_str(identity->reject_detail));
        }
        return SDCP_HOST_NO_MATCH;
    }
    fprintf(opt->log, "matched finger: %s\n", sub_factor_str(identity->sub_factor));

    // m == MAC(s, "identify"||n||id)
    if (sdcpcli_mac_identity(
            &session->keys,
            nonce, sizeof(nonce),
            identity->id, sizeof(identity->id),
            expected, sizeof(expected)) != 0)
    {
        return SDCP_HOST_ERR_CRYPTO;
    }

    if (!ct_equal(identity->mac, expected, sizeof(expected)))
    {
        fprintf(opt->log, "FAIL: identify MAC\n");
        return SDCP_HOST_ERR_VERIFY;
    }
    fprintf(opt->log, "ok: identify MAC\n");
    sdcp_print_bytes(opt->log, "id", identity->id, sizeof(identity->id));

    return SDCP_HOST_OK;
}

int sdcp_session_save(const char* path, const sdcp_session* session)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
    {
        return -1;
    }

    uint8_t buf[sizeof(session_magic) + sizeof(session->keys) +
        sizeof(session->pk_d) + sizeof(session->h_f)];
    uint8_t* p = buf;
    memcpy(p, session_magic, sizeof(session_magic)); p += sizeof(session_magic);
    memcpy(p, &session->keys, sizeof(session->keys)); p += sizeof(session->keys);
    memcpy(p, session->pk_d, sizeof(session->pk_d)); p += sizeof(session->pk_d);
    memcpy(p, session->h_f, sizeof(session->h_f));

    int ok = write(fd, buf, sizeof(buf)) == (ssize_t)sizeof(buf);
    secure_zero_memory(buf, sizeof(buf));

    return (close(fd) == 0 && ok) ? 0 : -1;
}

int sdcp_session_load(const char* path, sdcp_session* session)
{
    memset(session, 0, sizeof(*session));

    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        return -1;
    }

    uint8_t buf[sizeof(session_magic) + sizeof(session->keys) +
        sizeof(session->pk_d) + sizeof(session->h_f)];
    int ok = read(fd, buf, sizeof(buf)) == (ssize_t)sizeof(buf) &&
        memcmp(buf, session_magic, sizeof(session_magic)) == 0;
    close(fd);

    if (ok)
    {
        const uint8_t* p = buf + sizeof(session_magic);
        memcpy(&session->keys, p, sizeof(session->keys)); p += sizeof(session->keys);
        memcpy(session->pk_d, p, sizeof(session->pk_d)); p += sizeof(session->pk_d);
        memcpy(session->h_f, p, sizeof(session->h_f));
        session->established = 1;
    }
    secure_zero_memory(buf, sizeof(buf));

    return ok ? 0 : -1;
}
