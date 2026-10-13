#ifndef SDCPHOST_H
#define SDCPHOST_H

#include <stdint.h>
#include <stdio.h>

#include "sdcpconstants.h"
#include "transport.h"

// State established by a successful connect, needed for reconnect.
typedef struct {
    int established;
    sdcp_application_keys keys;
    uint8_t pk_d[SDCP_PUBLIC_KEY_SIZE_V1];
    uint8_t h_f[SDCP_DIGEST_SIZE_V1];
} sdcp_session;

typedef struct {
    // PEM or DER file of trusted roots for the model certificate. If NULL the
    // certificate is parsed but its chain is not validated.
    const char* ca_path;
    // If set, the firmware hash must match.
    const uint8_t* expected_h_f;
    FILE* log;
} sdcp_host_options;

typedef enum {
    SDCP_HOST_OK = 0,
    SDCP_HOST_ERR_TRANSPORT = -1,
    SDCP_HOST_ERR_VERIFY = -2,    // A MAC, signature or certificate check failed.
    SDCP_HOST_ERR_CRYPTO = -3,
    SDCP_HOST_ERR_NO_SESSION = -4,
} sdcp_host_result;

sdcp_host_result sdcp_host_connect(
    sdcp_transport* t,
    const sdcp_host_options* opt,
    sdcp_session* session);

sdcp_host_result sdcp_host_reconnect(
    sdcp_transport* t,
    const sdcp_host_options* opt,
    const sdcp_session* session);

// Asks for a finger and verifies that the device's match result is bound to
// this session and a fresh nonce.
sdcp_host_result sdcp_host_identify(
    sdcp_transport* t,
    const sdcp_host_options* opt,
    const sdcp_session* session,
    sdcp_identity* identity);

const char* sdcp_host_result_str(sdcp_host_result r);

// The session file holds the application keys in the clear; it is created
// with owner-only permissions.
int sdcp_session_save(const char* path, const sdcp_session* session);
int sdcp_session_load(const char* path, sdcp_session* session);

void sdcp_print_bytes(FILE* out, const char* label, const uint8_t* bytes, size_t len);

#endif // SDCPHOST_H
