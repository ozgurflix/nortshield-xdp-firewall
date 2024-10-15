#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "filters.h"
#include "common.h"
#include <cjson/cJSON.h>
#include <time.h>

#define FILTERS_MAP_PATH "/sys/fs/bpf/filters_map"
#define FILTERS_JSON_PATH "data/filters.json"

int add_filter(uint32_t dst_ip, uint32_t dst_mask, char *filtername, uint16_t port, uint32_t id) {
    int map_fd = bpf_obj_get(FILTERS_MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    struct filter flt = {};
    flt.id = id;
    flt.dst_ip = dst_ip;
    flt.dst_mask = dst_mask;
    strncpy(flt.filtername, filtername, sizeof(flt.filtername)-1);
    flt.port = port;

    if (bpf_map_update_elem(map_fd, &flt.id, &flt, BPF_ANY)) {
        perror("bpf_map_update_elem");
        close(map_fd);
        return 1;
    }

    close(map_fd);

    FILE *fp = fopen(FILTERS_JSON_PATH, "r+");
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

    cJSON *filter = cJSON_CreateObject();
    cJSON_AddNumberToObject(filter, "id", id);
    cJSON_AddStringToObject(filter, "dst_ip", inet_ntoa(*(struct in_addr *)&dst_ip));
    cJSON_AddNumberToObject(filter, "dst_mask", dst_mask);
    cJSON_AddStringToObject(filter, "filtername", filtername);
    cJSON_AddNumberToObject(filter, "port", port);

    cJSON_AddItemToArray(json, filter);

    char *out = cJSON_Print(json);
    fseek(fp, 0, SEEK_SET);
    fprintf(fp, "%s", out);
    fclose(fp);
    cJSON_Delete(json);
    free(out);

    return 0;
}

void manage_filters() {
    char filtername[32], dst[32];
    uint16_t port;
    printf("Enter filter name (SAMP/RAGEMP/TeamSpeak3): ");
    scanf("%s", filtername);
    printf("Enter destination IP (with subnet, e.g., 10.0.0.0/24): ");
    scanf("%s", dst);
    printf("Enter port: ");
    scanf("%hu", &port);

    uint32_t dst_ip, dst_mask;
    char *slash = strchr(dst, '/');
    if (slash) {
        *slash = '\0';
        dst_mask = atoi(slash + 1);
    } else {
        dst_mask = 32;
    }
    inet_pton(AF_INET, dst, &dst_ip);

    FILE *fp = fopen("data/filters.json", "r");
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

    add_filter(dst_ip, dst_mask, filtername, port, id);
}
