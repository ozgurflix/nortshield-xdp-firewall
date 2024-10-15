#ifndef RULES_H
#define RULES_H

#define MAX_RULES 1024

enum action {
    ACTION_DROP,
    ACTION_ACCEPT
};

struct rule {
    uint32_t id;
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint8_t protocol;
    char contain[32];
    enum action action;
};

#endif // RULES_H
