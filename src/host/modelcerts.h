#ifndef SDCPMODELCERTS_H
#define SDCPMODELCERTS_H

#include <stddef.h>
#include <stdint.h>

// A model certificate and the two intermediates above it. Devices send only
// the leaf; the host supplies the intermediates, as the Windows adapter does.
typedef struct {
    const char* name;
    const uint8_t* leaf;
    size_t leaf_len;
    const uint8_t* ca1;
    size_t ca1_len;
    const uint8_t* ca2;
    size_t ca2_len;
    int legacy; // Accepted only on request (the adapter's AutoDetect setting).
} sdcp_model_chain;

extern const sdcp_model_chain g_sdcp_model_chains[];
extern const size_t g_sdcp_model_chain_count;

#endif // SDCPMODELCERTS_H
