#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "common.h"
#include "rules.h"
#include "filters.h"

struct bpf_map_def SEC("maps") rules_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(enum action),
    .max_entries = MAX_RULES,
};

struct bpf_map_def SEC("maps") filters_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct filter),
    .max_entries = MAX_FILTERS,
};

struct bpf_map_def SEC("maps") log_map = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 1 << 24,
};

struct log_event {
    uint32_t timestamp;
    uint32_t dst_ip;
    uint32_t mbit;
    uint32_t pps;
} __attribute__((packed));

SEC("xdp")
int xdp_firewall_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    uint8_t protocol = ip->protocol;
    uint32_t src_ip = ip->saddr;
    uint32_t dst_ip = ip->daddr;

    struct block_key key = {};
    key.src_ip = src_ip;
    key.dst_ip = dst_ip;
    key.protocol = protocol;

    if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.dst_port = udp->dest;
    } else if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.dst_port = tcp->dest;
    } else {
        key.dst_port = 0;
    }

    enum action *act = bpf_map_lookup_elem(&rules_map, &key.dst_ip);
    if (act && *act == ACTION_DROP)
        return XDP_DROP;

    struct filter *flt = bpf_map_lookup_elem(&filters_map, &dst_ip);
    if (flt && flt->port == key.dst_port) {
        struct log_event *e;

        e = bpf_ringbuf_reserve(&log_map, sizeof(*e), 0);
        if (!e)
            return XDP_DROP;

        e->timestamp = bpf_ktime_get_ns() / 1000000; // Convert to milliseconds
        e->dst_ip = dst_ip;
        e->mbit = 0;
        e->pps = 0; 

        bpf_ringbuf_submit(e, 0);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
