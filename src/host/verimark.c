#define _POSIX_C_SOURCE 200809L // nanosleep

#include <libusb.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "host.h"
#include "transport.h"

// VeriMark command framing, reconstructed from USB captures of the Windows
// driver. Every command is a 12-byte header on bulk OUT:
//
//   flags(1) || cmd(1) || p1(1) || p2(1) || zero(6) || len(LE16)
//
// followed by len bytes of data on bulk OUT (flags bit 7) or bulk IN
// (flags bit 6), and a 5-byte status on bulk IN: code(1) || value(LE32).
// A non-zero code is a failure. SDCP values inside the data are
// LE16-length-prefixed fields.

#define VM_HEADER_SIZE 12
#define VM_STATUS_SIZE 5

#define VM_CMD_CONNECT          0x01 // OUT: r_h, pk_h
#define VM_CMD_CONNECT_RESPONSE 0x02 // IN:  r_d, claim, m
#define VM_CMD_RECONNECT        0x03 // OUT: r_h
#define VM_CMD_RECONNECT_MAC    0x04 // IN:  m
#define VM_CMD_CAPTURE_BEGIN    0x05
#define VM_CMD_CAPTURE_STATUS   0x06 // IN:  first byte 1 while waiting for a finger
#define VM_CMD_MATCH            0x08 // IN
#define VM_CMD_ENROLLMENTS      0x0e // IN
#define VM_CMD_IDENTIFY_NONCE   0x0b // OUT: n
#define VM_CMD_IDENTIFY_RESULT  0x0c // IN:  code || ? || id || m || trailer
#define VM_CMD_CAPTURE_END      0x11

// Response sizes the Windows driver requests.
#define VM_CONNECT_RESPONSE_SIZE 0x4b6
#define VM_ENROLLMENTS_SIZE      0x208
#define VM_IDENTIFY_RESULT_SIZE  0x4a
#define VM_POLL_INTERVAL_MS      80

typedef struct {
    libusb_context* usb;
    libusb_device_handle* handle;
    sdcp_usb_config config;
    uint8_t buf[4096];
} usb_ctx;

static void sleep_ms(unsigned int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static int bulk(sdcp_transport* t, uint8_t ep, uint8_t* data, size_t len, size_t* transferred)
{
    usb_ctx* ctx = t->ctx;
    int n = 0;

    int err = libusb_bulk_transfer(ctx->handle, ep, data, (int)len, &n, ctx->config.timeout_ms);
    if (err != 0)
    {
        fprintf(t->log, "usb: transfer on endpoint 0x%02x failed: %s\n", ep, libusb_strerror(err));
        return -1;
    }

    *transferred = (size_t)n;
    return 0;
}

// Runs one command. out is sent, or up to in_len bytes are read into in;
// at most one of the two may be set.
static int vm_command(
    sdcp_transport* t,
    uint8_t flags, uint8_t cmd, uint8_t p1, uint8_t p2,
    const uint8_t* out, size_t out_len,
    uint8_t* in, size_t in_len, size_t* in_got)
{
    usb_ctx* ctx = t->ctx;
    const size_t len = out != NULL ? out_len : in_len;
    size_t n = 0;

    uint8_t header[VM_HEADER_SIZE] = { flags, cmd, p1, p2 };
    header[10] = (uint8_t)len;
    header[11] = (uint8_t)(len >> 8);

    if (t->verbose)
    {
        sdcp_print_bytes(t->log, "> header", header, sizeof(header));
    }
    if (bulk(t, ctx->config.ep_out, header, sizeof(header), &n) != 0)
    {
        return -1;
    }

    if (out != NULL)
    {
        if (t->verbose)
        {
            sdcp_print_bytes(t->log, "> data", out, out_len);
        }
        if (bulk(t, ctx->config.ep_out, (uint8_t*)out, out_len, &n) != 0 || n != out_len)
        {
            return -1;
        }
    }
    else if (in != NULL)
    {
        size_t got = 0;
        while (got < in_len)
        {
            if (bulk(t, ctx->config.ep_in, in + got, in_len - got, &n) != 0)
            {
                return -1;
            }
            got += n;
            if (n == 0 || n % 512 != 0)
            {
                break; // Short packet ends the transfer.
            }
        }
        if (in_got != NULL)
        {
            *in_got = got;
        }
        if (t->verbose)
        {
            sdcp_print_bytes(t->log, "< data", in, got);
        }
    }

    uint8_t status[VM_STATUS_SIZE + 59];
    if (bulk(t, ctx->config.ep_in, status, sizeof(status), &n) != 0)
    {
        return -1;
    }
    if (t->verbose)
    {
        sdcp_print_bytes(t->log, "< status", status, n);
    }
    if (n != VM_STATUS_SIZE || status[0] != 0)
    {
        fprintf(t->log, "device: command 0x%02x failed with status %02x %08x\n",
            cmd, status[0],
            n >= VM_STATUS_SIZE ? (unsigned)(status[1] | status[2] << 8 | status[3] << 16 | (unsigned)status[4] << 24) : 0u);
        return -1;
    }

    return 0;
}

static size_t put_field(uint8_t* out, const uint8_t* data, size_t len)
{
    out[0] = (uint8_t)len;
    out[1] = (uint8_t)(len >> 8);
    memcpy(out + 2, data, len);
    return 2 + len;
}

static int vm_connect(
    sdcp_transport* t,
    const uint8_t* r_h, const uint8_t* pk_h,
    sdcp_connect_response* resp)
{
    usb_ctx* ctx = t->ctx;
    uint8_t req[2 + SDCP_RANDOM_SIZE_V1 + 2 + SDCP_PUBLIC_KEY_SIZE_V1];
    size_t len = put_field(req, r_h, SDCP_RANDOM_SIZE_V1);
    len += put_field(req + len, pk_h, SDCP_PUBLIC_KEY_SIZE_V1);

    size_t got = 0;
    if (vm_command(t, 0x85, VM_CMD_CONNECT, 0, 0, req, len, NULL, 0, NULL) != 0 ||
        vm_command(t, 0x45, VM_CMD_CONNECT_RESPONSE, 0, 0, NULL, 0,
            ctx->buf, VM_CONNECT_RESPONSE_SIZE, &got) != 0)
    {
        return -1;
    }

    if (sdcp_parse_connect_response(ctx->buf, got, resp) != 0)
    {
        fprintf(t->log, "device: could not parse the %zu-byte connect response\n", got);
        return -1;
    }

    return 0;
}

static int vm_reconnect(sdcp_transport* t, const uint8_t* r_h, uint8_t mac[SDCP_DIGEST_SIZE_V1])
{
    uint8_t req[2 + SDCP_RANDOM_SIZE_V1];
    uint8_t resp[2 + SDCP_DIGEST_SIZE_V1];
    size_t got = 0;

    if (vm_command(t, 0x85, VM_CMD_RECONNECT, 0, 0,
            req, put_field(req, r_h, SDCP_RANDOM_SIZE_V1), NULL, 0, NULL) != 0 ||
        vm_command(t, 0x45, VM_CMD_RECONNECT_MAC, 0, 0, NULL, 0, resp, sizeof(resp), &got) != 0)
    {
        return -1;
    }

    if (got != sizeof(resp) || resp[0] != SDCP_DIGEST_SIZE_V1 || resp[1] != 0)
    {
        fprintf(t->log, "device: unexpected reconnect response\n");
        return -1;
    }

    memcpy(mac, resp + 2, SDCP_DIGEST_SIZE_V1);
    return 0;
}

static int vm_identify(
    sdcp_transport* t,
    const uint8_t* nonce, size_t nonce_len,
    sdcp_identity* identity)
{
    usb_ctx* ctx = t->ctx;
    uint8_t poll[VM_STATUS_SIZE];
    size_t got = 0;
    int err = -1;

    if (vm_command(t, 0x05, VM_CMD_CAPTURE_BEGIN, 0x02, 0x02, NULL, 0, NULL, 0, NULL) != 0)
    {
        return -1;
    }

    fprintf(t->log, "touch the sensor...\n");
    fflush(t->log);

    // The status poll is too chatty to dump.
    const int verbose = t->verbose;
    t->verbose = 0;
    unsigned int waited = 0;
    for (;;)
    {
        if (vm_command(t, 0x45, VM_CMD_CAPTURE_STATUS, 0x02, 0x02, NULL, 0,
                poll, sizeof(poll), &got) != 0)
        {
            goto exit;
        }
        if (got > 0 && poll[0] == 0)
        {
            break;
        }
        if (waited >= ctx->config.finger_timeout_ms)
        {
            fprintf(t->log, "timed out waiting for a finger\n");
            goto exit;
        }
        sleep_ms(VM_POLL_INTERVAL_MS);
        waited += VM_POLL_INTERVAL_MS;
    }
    t->verbose = verbose;

    uint8_t match[9];
    uint8_t result[VM_IDENTIFY_RESULT_SIZE];
    if (vm_command(t, 0x45, VM_CMD_MATCH, 0x02, 0x00, NULL, 0, match, sizeof(match), &got) != 0 ||
        vm_command(t, 0x45, VM_CMD_ENROLLMENTS, 0, 0, NULL, 0,
            ctx->buf, VM_ENROLLMENTS_SIZE, &got) != 0 ||
        vm_command(t, 0x85, VM_CMD_IDENTIFY_NONCE, 0, 0, nonce, nonce_len, NULL, 0, NULL) != 0 ||
        vm_command(t, 0x45, VM_CMD_IDENTIFY_RESULT, 0x00, 0x02, NULL, 0,
            result, sizeof(result), &got) != 0)
    {
        goto exit;
    }

    // code(1) || unknown(1) || id(32) || m(32) || trailer(8). The meaning of
    // the second byte and the trailer is unknown; neither is MACed.
    if (got < 2 + 2 * SDCP_DIGEST_SIZE_V1)
    {
        fprintf(t->log, "device: identify result too short (%zu bytes)\n", got);
        goto exit;
    }
    if (result[0] != 0)
    {
        fprintf(t->log, "device: no match (result code %02x)\n", result[0]);
        goto exit;
    }

    memcpy(identity->id, result + 2, SDCP_DIGEST_SIZE_V1);
    memcpy(identity->mac, result + 2 + SDCP_DIGEST_SIZE_V1, SDCP_DIGEST_SIZE_V1);
    err = 0;

exit:
    t->verbose = verbose;
    // Always leave capture mode, as the Windows driver does.
    if (vm_command(t, 0x05, VM_CMD_CAPTURE_END, 0, 0, NULL, 0, NULL, 0, NULL) != 0)
    {
        err = -1;
    }

    return err;
}

static void usb_close(sdcp_transport* t)
{
    usb_ctx* ctx = t->ctx;
    if (ctx == NULL)
    {
        return;
    }

    if (ctx->handle != NULL)
    {
        libusb_release_interface(ctx->handle, ctx->config.interface_number);
        libusb_close(ctx->handle);
    }
    libusb_exit(ctx->usb);
    free(ctx);
    t->ctx = NULL;
}

int sdcp_usb_open(const sdcp_usb_config* config, sdcp_transport* t)
{
    usb_ctx* ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
    {
        return -1;
    }

    ctx->config = *config;
    t->ctx = ctx;
    t->connect = vm_connect;
    t->reconnect = vm_reconnect;
    t->identify = vm_identify;
    t->close = usb_close;

    int err = libusb_init(&ctx->usb);
    if (err != 0)
    {
        fprintf(stderr, "usb: init failed: %s\n", libusb_strerror(err));
        free(ctx);
        t->ctx = NULL;
        return -1;
    }

    libusb_device** list = NULL;
    ssize_t count = libusb_get_device_list(ctx->usb, &list);
    err = LIBUSB_ERROR_NO_DEVICE;
    for (ssize_t i = 0; i < count; i++)
    {
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(list[i], &desc) == 0 &&
            desc.idVendor == config->vid && desc.idProduct == config->pid)
        {
            err = libusb_open(list[i], &ctx->handle);
            break;
        }
    }
    libusb_free_device_list(list, 1);

    if (err != 0)
    {
        fprintf(stderr, "usb: cannot open %04x:%04x: %s\n",
            config->vid, config->pid, libusb_strerror(err));
        if (err == LIBUSB_ERROR_ACCESS)
        {
            fprintf(stderr, "usb: run as root or add a udev rule granting access to the device\n");
        }
        usb_close(t);
        return -1;
    }

    libusb_set_auto_detach_kernel_driver(ctx->handle, 1);
    err = libusb_claim_interface(ctx->handle, config->interface_number);
    if (err != 0)
    {
        fprintf(stderr, "usb: cannot claim interface %d: %s\n",
            config->interface_number, libusb_strerror(err));
        libusb_close(ctx->handle);
        ctx->handle = NULL;
        usb_close(t);
        return -1;
    }

    // Drop anything left queued by an earlier, interrupted session.
    int n = 0;
    while (libusb_bulk_transfer(ctx->handle, config->ep_in, ctx->buf, sizeof(ctx->buf), &n, 50) == 0 && n > 0)
    {
    }

    return 0;
}

static void describe_device(libusb_device* dev, const struct libusb_device_descriptor* desc, FILE* out)
{
    fprintf(out, "%04x:%04x  bus %03u device %03u\n",
        desc->idVendor, desc->idProduct,
        libusb_get_bus_number(dev), libusb_get_device_address(dev));

    libusb_device_handle* handle = NULL;
    if (libusb_open(dev, &handle) == 0)
    {
        unsigned char str[256];
        if (desc->iManufacturer &&
            libusb_get_string_descriptor_ascii(handle, desc->iManufacturer, str, sizeof(str)) > 0)
        {
            fprintf(out, "  manufacturer: %s\n", str);
        }
        if (desc->iProduct &&
            libusb_get_string_descriptor_ascii(handle, desc->iProduct, str, sizeof(str)) > 0)
        {
            fprintf(out, "  product:      %s\n", str);
        }
        if (desc->iSerialNumber &&
            libusb_get_string_descriptor_ascii(handle, desc->iSerialNumber, str, sizeof(str)) > 0)
        {
            fprintf(out, "  serial:       %s\n", str);
        }
        libusb_close(handle);
    }
    else
    {
        fprintf(out, "  (no permission to read string descriptors)\n");
    }

    struct libusb_config_descriptor* cfg = NULL;
    if (libusb_get_active_config_descriptor(dev, &cfg) != 0)
    {
        return;
    }

    static const char* transfer_types[] = { "control", "isochronous", "bulk", "interrupt" };
    for (int i = 0; i < cfg->bNumInterfaces; i++)
    {
        for (int a = 0; a < cfg->interface[i].num_altsetting; a++)
        {
            const struct libusb_interface_descriptor* intf = &cfg->interface[i].altsetting[a];
            fprintf(out, "  interface %u alt %u: class 0x%02x subclass 0x%02x protocol 0x%02x\n",
                intf->bInterfaceNumber, intf->bAlternateSetting,
                intf->bInterfaceClass, intf->bInterfaceSubClass, intf->bInterfaceProtocol);
            for (int e = 0; e < intf->bNumEndpoints; e++)
            {
                const struct libusb_endpoint_descriptor* ep = &intf->endpoint[e];
                fprintf(out, "    endpoint 0x%02x %-3s %-11s max packet %u\n",
                    ep->bEndpointAddress,
                    (ep->bEndpointAddress & LIBUSB_ENDPOINT_IN) ? "IN" : "OUT",
                    transfer_types[ep->bmAttributes & 0x03],
                    ep->wMaxPacketSize);
            }
        }
    }
    libusb_free_config_descriptor(cfg);
}

int sdcp_usb_describe(const sdcp_usb_config* config, int match_all, FILE* out)
{
    libusb_context* usb = NULL;
    int err = libusb_init(&usb);
    if (err != 0)
    {
        fprintf(stderr, "usb: init failed: %s\n", libusb_strerror(err));
        return -1;
    }

    libusb_device** list = NULL;
    ssize_t count = libusb_get_device_list(usb, &list);
    int found = 0;
    for (ssize_t i = 0; i < count; i++)
    {
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(list[i], &desc) != 0)
        {
            continue;
        }
        if (match_all || (desc.idVendor == config->vid && desc.idProduct == config->pid))
        {
            describe_device(list[i], &desc, out);
            found++;
        }
    }
    libusb_free_device_list(list, 1);
    libusb_exit(usb);

    if (found == 0)
    {
        fprintf(out, "no device %04x:%04x found\n", config->vid, config->pid);
        return -1;
    }

    return 0;
}
