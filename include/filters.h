#ifndef FILTERS_H
#define FILTERS_H

#define MAX_FILTERS 1024

struct filter {
    uint32_t id;
    uint32_t dst_ip;
    uint32_t dst_mask;
    char filtername[32];
    uint16_t port;
};

#endif // FILTERS_H
