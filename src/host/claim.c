#include <string.h>

#include "transport.h"

typedef struct { const uint8_t* ptr; size_t remaining; } reader;

static const uint8_t* take(reader* r, size_t len)
{
    if (r->remaining < len)
    {
        return NULL;
    }

    const uint8_t* p = r->ptr;
    r->ptr += len;
    r->remaining -= len;
    return p;
}

// Reads a LE16 length followed by that many bytes.
static const uint8_t* take_field(reader* r, size_t* len)
{
    const uint8_t* hdr = take(r, 2);
    if (hdr == NULL)
    {
        return NULL;
    }

    *len = (size_t)hdr[0] | ((size_t)hdr[1] << 8);
    return take(r, *len);
}

// Length of the DER SEQUENCE at the start of buf, including its header.
static size_t der_sequence_len(const uint8_t* buf, size_t len)
{
    if (len < 2 || buf[0] != 0x30)
    {
        return 0;
    }

    if ((buf[1] & 0x80) == 0)
    {
        return 2 + (size_t)buf[1];
    }

    size_t n = buf[1] & 0x7f;
    if (n == 0 || n > 3 || len < 2 + n)
    {
        return 0;
    }

    size_t body = 0;
    for (size_t i = 0; i < n; i++)
    {
        body = (body << 8) | buf[2 + i];
    }
    return 2 + n + body;
}

int sdcp_split_claim(const uint8_t* claim, size_t claim_len, sdcp_connect_response* resp)
{
    reader r = { claim, claim_len };

    if (claim_len <= SDCP_CLAIM_FIXED_SIZE_V1)
    {
        return -1;
    }

    resp->cert_len = claim_len - SDCP_CLAIM_FIXED_SIZE_V1;
    if (der_sequence_len(claim, resp->cert_len) != resp->cert_len ||
        (resp->cert = take(&r, resp->cert_len)) == NULL ||
        (resp->pk_d = take(&r, SDCP_PUBLIC_KEY_SIZE_V1)) == NULL ||
        (resp->pk_f = take(&r, SDCP_PUBLIC_KEY_SIZE_V1)) == NULL ||
        (resp->h_f = take(&r, SDCP_DIGEST_SIZE_V1)) == NULL ||
        (resp->s_m = take(&r, SDCP_SIGNATURE_SIZE_V1)) == NULL ||
        (resp->s_d = take(&r, SDCP_SIGNATURE_SIZE_V1)) == NULL ||
        r.remaining != 0)
    {
        return -1;
    }

    return 0;
}

int sdcp_parse_connect_response(const uint8_t* buf, size_t len, sdcp_connect_response* resp)
{
    memset(resp, 0, sizeof(*resp));

    reader r = { buf, len };
    size_t r_d_len = 0, claim_len = 0, mac_len = 0;

    resp->device_random = take_field(&r, &r_d_len);
    const uint8_t* claim = take_field(&r, &claim_len);
    resp->mac = take_field(&r, &mac_len);

    if (resp->device_random == NULL || r_d_len != SDCP_RANDOM_SIZE_V1 ||
        claim == NULL ||
        resp->mac == NULL || mac_len != SDCP_DIGEST_SIZE_V1)
    {
        return -1;
    }

    return sdcp_split_claim(claim, claim_len, resp);
}
