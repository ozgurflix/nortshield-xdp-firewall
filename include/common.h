#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

struct block_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

#endif // COMMON_H
