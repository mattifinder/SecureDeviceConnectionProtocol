#include <stdlib.h>
#include <string.h>

#include "sdcpclient.h"
#include "transport.h"

// A simulated SDCP device, provisioned the same way as in sdcptest.

typedef struct {
    sdcp_mock_tamper tamper;
    sdcp_keypair model_key;
    sdcp_keypair device_key;
    sdcp_signature model_signature;
    sdcp_keypair firmware_key;
    sdcp_firmware_signature firmware_signature;
    uint8_t enrollment_id[SDCP_DIGEST_SIZE_V1];
    int has_session;
    sdcp_application_keys keys;

    // Backing storage for the last connect response.
    uint8_t r_d[SDCP_RANDOM_SIZE_V1];
    uint8_t mac[SDCP_DIGEST_SIZE_V1];
    sdcp_signature s_m;
    sdcp_firmware_signature sd;
} mock_ctx;

static int mock_connect(
    sdcp_transport* t,
    const uint8_t* r_h, const uint8_t* pk_h,
    sdcp_connect_response* resp)
{
    mock_ctx* ctx = t->ctx;
    uint8_t ms[SDCP_DIGEST_SIZE_V1] = { 0 };
    uint8_t claim_hash[SDCP_DIGEST_SIZE_V1] = { 0 };

    ctx->s_m = ctx->model_signature;
    ctx->sd = ctx->firmware_signature;

    // Corrupted signatures are MACed like the real ones, so that only the
    // signature checks can catch them.
    if (ctx->tamper == SDCP_MOCK_TAMPER_MODEL_SIGNATURE)
    {
        ctx->s_m.s[0] ^= 1;
    }
    if (ctx->tamper == SDCP_MOCK_TAMPER_DEVICE_SIGNATURE)
    {
        ctx->sd.sig.s[0] ^= 1;
    }

    if (sdcpcli_gen_rand(ctx->r_d, sizeof(ctx->r_d)) != 0 ||
        sdcpcli_derive_master_secret(
            pk_h, SDCP_PUBLIC_KEY_SIZE_V1,
            ctx->firmware_key.sk, sizeof(ctx->firmware_key.sk),
            r_h, SDCP_RANDOM_SIZE_V1,
            ctx->r_d, sizeof(ctx->r_d),
            ms, sizeof(ms)) != 0 ||
        sdcpcli_derive_application_keys(ms, sizeof(ms), &ctx->keys) != 0 ||
        sdcpcli_hash_claim(
            ctx->model_key.pk, sizeof(ctx->model_key.pk),
            ctx->device_key.pk, sizeof(ctx->device_key.pk),
            ctx->firmware_key.pk, sizeof(ctx->firmware_key.pk),
            &ctx->sd,
            &ctx->s_m,
            claim_hash, sizeof(claim_hash)) != 0 ||
        sdcpcli_mac_claim_hash(&ctx->keys, claim_hash, sizeof(claim_hash), ctx->mac, sizeof(ctx->mac)) != 0)
    {
        return -1;
    }
    ctx->has_session = 1;

    if (ctx->tamper == SDCP_MOCK_TAMPER_MAC)
    {
        ctx->mac[0] ^= 1;
    }

    resp->device_random = ctx->r_d;
    resp->cert = ctx->model_key.pk; // Raw key in place of the certificate.
    resp->cert_len = sizeof(ctx->model_key.pk);
    resp->pk_d = ctx->device_key.pk;
    resp->pk_f = ctx->firmware_key.pk;
    resp->h_f = ctx->sd.hash;
    resp->s_m = (const uint8_t*)&ctx->s_m;
    resp->s_d = (const uint8_t*)&ctx->sd.sig;
    resp->mac = ctx->mac;

    return 0;
}

static int mock_reconnect(sdcp_transport* t, const uint8_t* r_h, uint8_t mac[SDCP_DIGEST_SIZE_V1])
{
    mock_ctx* ctx = t->ctx;

    if (!ctx->has_session)
    {
        fprintf(t->log, "mock: no session to reconnect to\n");
        return -1;
    }

    if (sdcpcli_mac_reconnect(&ctx->keys, r_h, SDCP_RANDOM_SIZE_V1, mac, SDCP_DIGEST_SIZE_V1) != 0)
    {
        return -1;
    }

    if (ctx->tamper == SDCP_MOCK_TAMPER_MAC)
    {
        mac[0] ^= 1;
    }

    return 0;
}

static int mock_identify(
    sdcp_transport* t,
    const uint8_t* nonce, size_t nonce_len,
    sdcp_identity* identity)
{
    mock_ctx* ctx = t->ctx;

    if (!ctx->has_session)
    {
        fprintf(t->log, "mock: no session\n");
        return -1;
    }

    identity->matched = 1;
    identity->sub_factor = 2; // right index finger
    memcpy(identity->id, ctx->enrollment_id, sizeof(identity->id));
    if (sdcpcli_mac_identity(
            &ctx->keys,
            nonce, nonce_len,
            identity->id, sizeof(identity->id),
            identity->mac, sizeof(identity->mac)) != 0)
    {
        return -1;
    }

    if (ctx->tamper == SDCP_MOCK_TAMPER_MAC)
    {
        identity->mac[0] ^= 1;
    }

    return 0;
}

static void mock_close(sdcp_transport* t)
{
    if (t->ctx != NULL)
    {
        memset(t->ctx, 0, sizeof(mock_ctx));
        free(t->ctx);
        t->ctx = NULL;
    }
}

int sdcp_mock_open(sdcp_mock_tamper tamper, sdcp_transport* t)
{
    mock_ctx* ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
    {
        return -1;
    }
    ctx->tamper = tamper;

    // Factory provisioning, then the bootloader signing the firmware.
    const uint8_t firmware[] = { 'f', 'i', 'r', 'm', 'w', 'a', 'r', 'e' };
    uint8_t key_hash[SDCP_DIGEST_SIZE_V1] = { 0 };

    if (sdcpcli_keygen(&ctx->model_key) != 0 ||
        sdcpcli_keygen(&ctx->device_key) != 0 ||
        sdcpcli_hash(ctx->device_key.pk, sizeof(ctx->device_key.pk), key_hash, sizeof(key_hash)) != 0 ||
        sdcpcli_sign_hash(
            ctx->model_key.sk, sizeof(ctx->model_key.sk),
            key_hash, sizeof(key_hash),
            &ctx->model_signature) != 0 ||
        sdcpcli_sign_firmware(
            ctx->device_key.sk, sizeof(ctx->device_key.sk),
            firmware, sizeof(firmware),
            &ctx->firmware_key,
            &ctx->firmware_signature) != 0 ||
        sdcpcli_gen_rand(ctx->enrollment_id, sizeof(ctx->enrollment_id)) != 0)
    {
        free(ctx);
        return -1;
    }

    t->ctx = ctx;
    t->connect = mock_connect;
    t->reconnect = mock_reconnect;
    t->identify = mock_identify;
    t->close = mock_close;
    return 0;
}
