#ifndef SDCPTRANSPORT_H
#define SDCPTRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sdcpconstants.h"

// Device answer to a full connect. Pointers refer to transport-owned memory
// and stay valid until the next call on the transport.
typedef struct {
    const uint8_t* device_random; // r_d, SDCP_RANDOM_SIZE_V1
    const uint8_t* cert;          // cert_m, X.509 DER
    size_t cert_len;
    const uint8_t* pk_d;          // SDCP_PUBLIC_KEY_SIZE_V1
    const uint8_t* pk_f;          // SDCP_PUBLIC_KEY_SIZE_V1
    const uint8_t* h_f;           // SDCP_DIGEST_SIZE_V1
    const uint8_t* s_m;           // SDCP_SIGNATURE_SIZE_V1
    const uint8_t* s_d;           // SDCP_SIGNATURE_SIZE_V1
    const uint8_t* mac;           // m = MAC(s, "connect"||H(c))
} sdcp_connect_response;

// Fixed part of a claim after cert_m: pk_d || pk_f || h_f || s_m || s_d.
#define SDCP_CLAIM_FIXED_SIZE_V1 \
    (2 * SDCP_PUBLIC_KEY_SIZE_V1 + SDCP_DIGEST_SIZE_V1 + 2 * SDCP_SIGNATURE_SIZE_V1)

typedef struct {
    // Set when the device matched the finger; id and mac are valid only then.
    int matched;
    // Finger the match was made with (WINBIO_BIOMETRIC_SUBTYPE, ANSI 381
    // position: 1-5 right thumb..little, 6-10 left thumb..little).
    uint8_t sub_factor;
    // WINBIO_REJECT_DETAIL when the capture was rejected, otherwise 0.
    uint32_t reject_detail;
    uint8_t id[SDCP_DIGEST_SIZE_V1];  // Enrollment id stored with the template.
    uint8_t mac[SDCP_DIGEST_SIZE_V1]; // MAC(s, "identify"||n||id)
} sdcp_identity;

// The SDCP messages a device exchanges with the host. Each call returns 0 on
// success; failures are reported on the transport's log.
typedef struct sdcp_transport {
    int (*connect)(
        struct sdcp_transport* t,
        const uint8_t* r_h, const uint8_t* pk_h,
        sdcp_connect_response* resp);
    int (*reconnect)(
        struct sdcp_transport* t,
        const uint8_t* r_h,
        uint8_t mac[SDCP_DIGEST_SIZE_V1]);
    // Waits for a finger, matches it, and returns the authorized identity
    // for nonce n.
    int (*identify)(
        struct sdcp_transport* t,
        const uint8_t* nonce, size_t nonce_len,
        sdcp_identity* identity);
    void (*close)(struct sdcp_transport* t);
    void* ctx;
    FILE* log;
    int verbose;
} sdcp_transport;

typedef struct {
    uint16_t vid;
    uint16_t pid;
    int interface_number;
    uint8_t ep_out;
    uint8_t ep_in;
    unsigned int timeout_ms;        // Per USB transfer.
    unsigned int finger_timeout_ms; // How long identify waits for a finger.
} sdcp_usb_config;

// Kensington VeriMark Desktop 2.0 and its bulk endpoints.
#define SDCP_USB_DEFAULT_VID            0x047d
#define SDCP_USB_DEFAULT_PID            0x8228
#define SDCP_USB_DEFAULT_INTERFACE      0
#define SDCP_USB_DEFAULT_EP_OUT         0x01
#define SDCP_USB_DEFAULT_EP_IN          0x82
#define SDCP_USB_DEFAULT_TIMEOUT        5000
#define SDCP_USB_DEFAULT_FINGER_TIMEOUT 30000

int sdcp_usb_open(const sdcp_usb_config* config, sdcp_transport* t);

// Prints descriptors for devices matching config without sending anything.
// With match_all set, prints every attached device instead.
int sdcp_usb_describe(const sdcp_usb_config* config, int match_all, FILE* out);

// Splits an SDCP claim cert_m||pk_d||pk_f||h_f||s_m||s_d. As in the Windows
// adapter, the certificate is everything before the fixed-size tail; its DER
// header must agree. Returns 0 on success.
int sdcp_split_claim(const uint8_t* claim, size_t claim_len, sdcp_connect_response* resp);

// Parses the VeriMark connect response: LE16-length-prefixed r_d, claim and
// MAC fields, followed by zero padding. Returns 0 on success.
int sdcp_parse_connect_response(const uint8_t* buf, size_t len, sdcp_connect_response* resp);

typedef enum {
    SDCP_MOCK_TAMPER_NONE,
    SDCP_MOCK_TAMPER_MAC,
    SDCP_MOCK_TAMPER_MODEL_SIGNATURE,
    SDCP_MOCK_TAMPER_DEVICE_SIGNATURE,
} sdcp_mock_tamper;

// An in-process simulated device built on libsdcpcli. Its model
// "certificate" is the raw model public key, as in sdcptest.
int sdcp_mock_open(sdcp_mock_tamper tamper, sdcp_transport* t);

#endif // SDCPTRANSPORT_H
