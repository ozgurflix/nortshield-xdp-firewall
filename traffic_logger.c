#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"
#include <cjson/cJSON.h>
#include <arpa/inet.h>
#include <time.h>

#define LOG_JSON_PATH "data/logs.json"

struct log_event {
    uint32_t timestamp;
    uint32_t dst_ip;
    uint32_t mbit;
    uint32_t pps;
} __attribute__((packed));

static volatile int exiting = 0;

void handle_signal(int sig) {
    exiting = 1;
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    struct log_event *e = data;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->dst_ip, ip_str, sizeof(ip_str));

    // Get current timestamp
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "timestamp", time_str);
    cJSON_AddStringToObject(json, "dst_ip", ip_str);
    cJSON_AddNumberToObject(json, "mbit", e->mbit);
    cJSON_AddNumberToObject(json, "pps", e->pps);

    char *out = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    FILE *fp = fopen(LOG_JSON_PATH, "a");
    if (fp) {
        fprintf(fp, "%s\n", out);
        fclose(fp);
    }
    free(out);

    return 0;
}

static int handle_rb_event(void *ctx, void *data, size_t data_sz) {
    return handle_event(ctx, data, data_sz);
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    int map_fd;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    obj = bpf_object__open_file("xdp_firewall.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "log_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find log_map\n");
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_rb_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Logging dropped attacks...\n");

    while (!exiting) {
        ring_buffer__poll(rb, 100 /* timeout, ms */);
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
