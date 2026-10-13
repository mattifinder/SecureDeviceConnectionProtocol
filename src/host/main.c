#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"
#include "transport.h"

static void usage(FILE* out)
{
    fprintf(out,
        "usage: sdcpusb [options] <command>...\n"
        "\n"
        "Host side of the Secure Device Connection Protocol over USB.\n"
        "\n"
        "commands (run in order, sharing one session):\n"
        "  list        describe all attached USB devices (sends nothing)\n"
        "  info        describe the target device (sends nothing)\n"
        "  connect     full SDCP connect: key agreement and claim verification\n"
        "  reconnect   SDCP reconnect using the established session\n"
        "  identify    wait for a finger and verify the authorized identity\n"
        "\n"
        "options:\n"
        "  --vid HEX               USB vendor id (default %04x)\n"
        "  --pid HEX               USB product id (default %04x)\n"
        "  --interface N           interface to claim (default %d)\n"
        "  --ep-out HEX            bulk OUT endpoint (default 0x%02x)\n"
        "  --ep-in HEX             bulk IN endpoint (default 0x%02x)\n"
        "  --timeout MS            per-transfer timeout (default %d)\n"
        "  --finger-timeout MS     how long identify waits for a finger (default %d)\n"
        "  --session PATH          save the session after connect, load it for reconnect\n"
        "  --ca PATH               trusted roots (PEM/DER) for the model certificate\n"
        "  --expect-fw-hash HEX    required firmware hash h_f (64 hex digits)\n"
        "  --mock                  talk to a simulated device instead of USB\n"
        "  --mock-tamper FIELD     make the mock corrupt: mac, model-sig, device-sig\n"
        "  -v, --verbose           dump raw requests and responses\n"
        "  -h, --help              show this help\n",
        SDCP_USB_DEFAULT_VID, SDCP_USB_DEFAULT_PID, SDCP_USB_DEFAULT_INTERFACE,
        SDCP_USB_DEFAULT_EP_OUT, SDCP_USB_DEFAULT_EP_IN, SDCP_USB_DEFAULT_TIMEOUT,
        SDCP_USB_DEFAULT_FINGER_TIMEOUT);
}

static int parse_hex_ul(const char* s, unsigned long max, unsigned long* out)
{
    char* end = NULL;
    unsigned long v = strtoul(s, &end, 16);
    if (end == s || *end != '\0' || v > max)
    {
        return -1;
    }
    *out = v;
    return 0;
}

static int parse_hex_bytes(const char* s, uint8_t* out, size_t len)
{
    if (strlen(s) != len * 2)
    {
        return -1;
    }
    for (size_t i = 0; i < len; i++)
    {
        char byte[3] = { s[2 * i], s[2 * i + 1], 0 };
        unsigned long v = 0;
        if (parse_hex_ul(byte, 0xff, &v) != 0)
        {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(int argc, char** argv)
{
    sdcp_usb_config usb = {
        SDCP_USB_DEFAULT_VID, SDCP_USB_DEFAULT_PID, SDCP_USB_DEFAULT_INTERFACE,
        SDCP_USB_DEFAULT_EP_OUT, SDCP_USB_DEFAULT_EP_IN, SDCP_USB_DEFAULT_TIMEOUT,
        SDCP_USB_DEFAULT_FINGER_TIMEOUT
    };
    sdcp_host_options opt = { NULL, NULL, stdout };
    int verbose = 0;
    const char* session_path = NULL;
    int mock = 0;
    sdcp_mock_tamper tamper = SDCP_MOCK_TAMPER_NONE;
    uint8_t expected_h_f[SDCP_DIGEST_SIZE_V1];

    enum { OPT_VID = 256, OPT_PID, OPT_INTERFACE, OPT_EP_OUT, OPT_EP_IN, OPT_TIMEOUT, OPT_FINGER_TIMEOUT,
        OPT_SESSION, OPT_CA, OPT_FW_HASH, OPT_MOCK, OPT_MOCK_TAMPER };
    static const struct option long_options[] = {
        { "vid", required_argument, NULL, OPT_VID },
        { "pid", required_argument, NULL, OPT_PID },
        { "interface", required_argument, NULL, OPT_INTERFACE },
        { "ep-out", required_argument, NULL, OPT_EP_OUT },
        { "ep-in", required_argument, NULL, OPT_EP_IN },
        { "timeout", required_argument, NULL, OPT_TIMEOUT },
        { "finger-timeout", required_argument, NULL, OPT_FINGER_TIMEOUT },
        { "session", required_argument, NULL, OPT_SESSION },
        { "ca", required_argument, NULL, OPT_CA },
        { "expect-fw-hash", required_argument, NULL, OPT_FW_HASH },
        { "mock", no_argument, NULL, OPT_MOCK },
        { "mock-tamper", required_argument, NULL, OPT_MOCK_TAMPER },
        { "verbose", no_argument, NULL, 'v' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int c;
    unsigned long v;
    while ((c = getopt_long(argc, argv, "vh", long_options, NULL)) != -1)
    {
        switch (c)
        {
        case OPT_VID:
        case OPT_PID:
            if (parse_hex_ul(optarg, 0xffff, &v) != 0)
            {
                fprintf(stderr, "invalid id: %s\n", optarg);
                return 2;
            }
            *(c == OPT_VID ? &usb.vid : &usb.pid) = (uint16_t)v;
            break;
        case OPT_EP_OUT:
        case OPT_EP_IN:
            if (parse_hex_ul(optarg, 0xff, &v) != 0)
            {
                fprintf(stderr, "invalid endpoint: %s\n", optarg);
                return 2;
            }
            *(c == OPT_EP_OUT ? &usb.ep_out : &usb.ep_in) = (uint8_t)v;
            break;
        case OPT_INTERFACE:
            usb.interface_number = atoi(optarg);
            break;
        case OPT_TIMEOUT:
            usb.timeout_ms = (unsigned int)strtoul(optarg, NULL, 10);
            break;
        case OPT_FINGER_TIMEOUT:
            usb.finger_timeout_ms = (unsigned int)strtoul(optarg, NULL, 10);
            break;
        case OPT_SESSION:
            session_path = optarg;
            break;
        case OPT_CA:
            opt.ca_path = optarg;
            break;
        case OPT_FW_HASH:
            if (parse_hex_bytes(optarg, expected_h_f, sizeof(expected_h_f)) != 0)
            {
                fprintf(stderr, "--expect-fw-hash needs %zu hex digits\n", sizeof(expected_h_f) * 2);
                return 2;
            }
            opt.expected_h_f = expected_h_f;
            break;
        case OPT_MOCK:
            mock = 1;
            break;
        case OPT_MOCK_TAMPER:
            mock = 1;
            if (strcmp(optarg, "mac") == 0) tamper = SDCP_MOCK_TAMPER_MAC;
            else if (strcmp(optarg, "model-sig") == 0) tamper = SDCP_MOCK_TAMPER_MODEL_SIGNATURE;
            else if (strcmp(optarg, "device-sig") == 0) tamper = SDCP_MOCK_TAMPER_DEVICE_SIGNATURE;
            else
            {
                fprintf(stderr, "unknown --mock-tamper field: %s\n", optarg);
                return 2;
            }
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage(stdout);
            return 0;
        default:
            usage(stderr);
            return 2;
        }
    }

    if (optind >= argc)
    {
        usage(stderr);
        return 2;
    }

    for (int i = optind; i < argc; i++)
    {
        if (strcmp(argv[i], "list") != 0 && strcmp(argv[i], "info") != 0 &&
            strcmp(argv[i], "connect") != 0 && strcmp(argv[i], "reconnect") != 0 &&
            strcmp(argv[i], "identify") != 0)
        {
            fprintf(stderr, "unknown command: %s\n", argv[i]);
            usage(stderr);
            return 2;
        }
    }

    sdcp_transport transport = { 0 };
    transport.log = stdout;
    transport.verbose = verbose;
    sdcp_session session = { 0 };
    int status = 0;

    for (int i = optind; i < argc && status == 0; i++)
    {
        const char* cmd = argv[i];

        if (strcmp(cmd, "list") == 0 || strcmp(cmd, "info") == 0)
        {
            if (mock)
            {
                printf("simulated SDCP device (libsdcpcli)\n");
            }
            else if (sdcp_usb_describe(&usb, strcmp(cmd, "list") == 0, stdout) != 0)
            {
                status = 1;
            }
            continue;
        }

        if (transport.ctx == NULL)
        {
            if (mock)
            {
                if (sdcp_mock_open(tamper, &transport) != 0)
                {
                    fprintf(stderr, "could not create the simulated device\n");
                    status = 1;
                    break;
                }
            }
            else if (sdcp_usb_open(&usb, &transport) != 0)
            {
                status = 1;
                break;
            }
        }

        sdcp_host_result r;
        if (strcmp(cmd, "connect") == 0)
        {
            printf("== connect\n");
            r = sdcp_host_connect(&transport, &opt, &session);
            if (r == SDCP_HOST_OK && session_path != NULL)
            {
                if (sdcp_session_save(session_path, &session) != 0)
                {
                    fprintf(stderr, "could not save session to %s\n", session_path);
                    status = 1;
                }
                else
                {
                    printf("session saved to %s\n", session_path);
                }
            }
        }
        else
        {
            printf("== %s\n", cmd);
            if (!session.established && session_path != NULL &&
                sdcp_session_load(session_path, &session) != 0)
            {
                fprintf(stderr, "could not load session from %s\n", session_path);
            }
            if (strcmp(cmd, "reconnect") == 0)
            {
                r = sdcp_host_reconnect(&transport, &opt, &session);
            }
            else
            {
                sdcp_identity identity;
                r = sdcp_host_identify(&transport, &opt, &session, &identity);
            }
        }

        printf("%s: %s\n", cmd, sdcp_host_result_str(r));
        if (r != SDCP_HOST_OK)
        {
            status = 1;
        }
    }

    if (transport.ctx != NULL)
    {
        transport.close(&transport);
    }
    memset(&session, 0, sizeof(session));

    return status;
}
