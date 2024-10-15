#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "rules.h"
#include "common.h"
#include <cjson/cJSON.h>
#include <time.h>

#define RULES_MAP_PATH "/sys/fs/bpf/rules_map"
#define RULES_JSON_PATH "data/rules.json"

int add_rule(uint32_t src_ip, uint32_t src_mask, uint32_t dst_ip, uint32_t dst_mask, uint8_t protocol, char *contain, enum action act, uint32_t id) {
    int map_fd = bpf_obj_get(RULES_MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    if (bpf_map_update_elem(map_fd, &id, &act, BPF_ANY)) {
        perror("bpf_map_update_elem");
        close(map_fd);
        return 1;
    }

    close(map_fd);

    // Update JSON
    FILE *fp = fopen(RULES_JSON_PATH, "r+");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_data = malloc(fsize + 1);
    fread(json_data, 1, fsize, fp);
    json_data[fsize] = 0;

    cJSON *json = cJSON_Parse(json_data);
    free(json_data);
    if (!json) {
        fclose(fp);
        return 1;
    }

    cJSON *rule = cJSON_CreateObject();
    cJSON_AddNumberToObject(rule, "id", id);
    cJSON_AddStringToObject(rule, "src_ip", inet_ntoa(*(struct in_addr *)&src_ip));
    cJSON_AddNumberToObject(rule, "src_mask", src_mask);
    cJSON_AddStringToObject(rule, "dst_ip", inet_ntoa(*(struct in_addr *)&dst_ip));
    cJSON_AddNumberToObject(rule, "dst_mask", dst_mask);
    cJSON_AddStringToObject(rule, "protocol", protocol == IPPROTO_UDP ? "UDP" : "TCP");
    cJSON_AddStringToObject(rule, "contain", contain);
    cJSON_AddStringToObject(rule, "action", act == ACTION_DROP ? "drop" : "accept");

    cJSON_AddItemToArray(json, rule);

    char *out = cJSON_Print(json);
    fseek(fp, 0, SEEK_SET);
    fprintf(fp, "%s", out);
    fclose(fp);
    cJSON_Delete(json);
    free(out);

    return 0;
}

void manage_rules() {
    char src[32], dst[32], protocol[8], contain[32], action_str[8];
    printf("Enter source IP (with subnet, e.g., 192.168.1.0/24): ");
    scanf("%s", src);
    printf("Enter destination IP (with subnet, e.g., 10.0.0.0/24): ");
    scanf("%s", dst);
    printf("Enter protocol (UDP/TCP): ");
    scanf("%s", protocol);
    printf("Enter contain (or NULL): ");
    scanf("%s", contain);
    printf("Enter action (drop/accept): ");
    scanf("%s", action_str);

    uint32_t src_ip, src_mask, dst_ip, dst_mask;
    int mask;

    // Source IP
    char *slash = strchr(src, '/');
    if (slash) {
        *slash = '\0';
        mask = atoi(slash + 1);
    } else {
        mask = 32;
    }
    inet_pton(AF_INET, src, &src_ip);
    src_mask = mask;

    slash = strchr(dst, '/');
    if (slash) {
        *slash = '\0';
        mask = atoi(slash + 1);
    } else {
        mask = 32;
    }
    inet_pton(AF_INET, dst, &dst_ip);
    dst_mask = mask;

    uint8_t proto;
    if (strcmp(protocol, "UDP") == 0)
        proto = IPPROTO_UDP;
    else if (strcmp(protocol, "TCP") == 0)
        proto = IPPROTO_TCP;
    else
        proto = 0;

    enum action act;
    if (strcmp(action_str, "drop") == 0)
        act = ACTION_DROP;
    else
        act = ACTION_ACCEPT;

    FILE *fp = fopen("data/rules.json", "r");
    uint32_t id = 1;
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        char *json_data = malloc(fsize + 1);
        fread(json_data, 1, fsize, fp);
        json_data[fsize] = 0;
        cJSON *json = cJSON_Parse(json_data);
        if (json) {
            int array_size = cJSON_GetArraySize(json);
            id = array_size + 1;
            cJSON_Delete(json);
        }
        free(json_data);
        fclose(fp);
    }

    add_rule(src_ip, src_mask, dst_ip, dst_mask, proto, strcmp(contain, "NULL") == 0 ? NULL : contain, act, id);
}
