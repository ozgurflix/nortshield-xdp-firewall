
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include "rules.h"
#include "filters.h"
#include "common.h"
#include <cjson/cJSON.h>

#define RULES_MAP_PATH "/sys/fs/bpf/rules_map"
#define FILTERS_MAP_PATH "/sys/fs/bpf/filters_map"
#define LOG_MAP_PATH "/sys/fs/bpf/log_map"

#define RULES_JSON_PATH "data/rules.json"
#define FILTERS_JSON_PATH "data/filters.json"
#define SAMP_WHITELIST_PATH "data/sampwhitelist.json"
#define SAMP_OYUNUCI_PATH "data/sampoyunici.json"
#define LOGS_JSON_PATH "data/logs.json"

int start_firewall(const char *iface);
int stop_firewall(const char *iface);
int add_rule_cli(int argc, char **argv);
int remove_rule_cli(int argc, char **argv);
int add_filter_cli(int argc, char **argv);
int remove_filter_cli(int argc, char **argv);
void print_usage(const char *prog);
int load_json(const char *path, cJSON **json);
int save_json(const char *path, cJSON *json);
uint32_t generate_unique_id(const char *json_path);
int add_rule_to_map(struct rule *r);
int remove_rule_from_map(uint32_t id);
int add_filter_to_map(struct filter *f);
int remove_filter_from_map(uint32_t id);
int initialize_data_files();

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (initialize_data_files() != 0) {
        fprintf(stderr, "Failed to initialize data files.\n");
        return 1;
    }

    if (strcmp(argv[1], "start") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s start <interface>\n", argv[0]);
            return 1;
        }
        return start_firewall(argv[2]);
    }
    else if (strcmp(argv[1], "stop") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s stop <interface>\n", argv[0]);
            return 1;
        }
        return stop_firewall(argv[2]);
    }
    else if (strcmp(argv[1], "add-rule") == 0) {
        return add_rule_cli(argc - 1, &argv[1]);
    }
    else if (strcmp(argv[1], "remove-rule") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s remove-rule <rule_id>\n", argv[0]);
            return 1;
        }
        uint32_t id = atoi(argv[2]);
        return remove_rule_from_map(id);
    }
    else if (strcmp(argv[1], "addfilter") == 0) {
        return add_filter_cli(argc - 1, &argv[1]);
    }
    else if (strcmp(argv[1], "removefilter") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s removefilter <filter_id>\n", argv[0]);
            return 1;
        }
        uint32_t id = atoi(argv[2]);
        return remove_filter_from_map(id);
    }
    else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}

void print_usage(const char *prog) {
    printf("Usage: %s <command> [options]\n", prog);
    printf("Commands:\n");
    printf("  start <interface>                        Start the firewall on the specified interface\n");
    printf("  stop <interface>                         Stop the firewall on the specified interface\n");
    printf("  add-rule                                 Add a new rule\n");
    printf("  remove-rule <rule_id>                    Remove a rule by its ID\n");
    printf("  addfilter <filtername> <dstip> <port>    Add a new filter\n");
    printf("  removefilter <filter_id>                 Remove a filter by its ID\n");
}

int initialize_data_files() {
    struct stat st = {0};

    if (stat("data", &st) == -1) {
        if (mkdir("data", 0755) != 0) {
            perror("mkdir data");
            return -1;
        }
    }

    const char *files[] = {RULES_JSON_PATH, FILTERS_JSON_PATH, SAMP_WHITELIST_PATH, SAMP_OYUNUCI_PATH, LOGS_JSON_PATH};
    for (int i = 0; i < 5; i++) {
        if (stat(files[i], &st) == -1) {
            FILE *fp = fopen(files[i], "w");
            if (!fp) {
                perror("fopen");
                return -1;
            }
            fprintf(fp, "[]\n");
            fclose(fp);
        }
    }

    return 0;
}

int load_json(const char *path, cJSON **json) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    char *data = malloc(fsize + 1);
    if (!data) {
        fclose(fp);
        return -1;
    }

    fread(data, 1, fsize, fp);
    data[fsize] = '\0';
    fclose(fp);

    *json = cJSON_Parse(data);
    free(data);

    if (!*json) {
        fprintf(stderr, "Error parsing JSON from %s\n", path);
        return -1;
    }

    return 0;
}

int save_json(const char *path, cJSON *json) {
    char *out = cJSON_PrintUnformatted(json);
    if (!out) {
        fprintf(stderr, "Error printing JSON\n");
        return -1;
    }

    FILE *fp = fopen(path, "w");
    if (!fp) {
        perror("fopen");
        free(out);
        return -1;
    }

    fprintf(fp, "%s\n", out);
    fclose(fp);
    free(out);

    return 0;
}

uint32_t generate_unique_id(const char *json_path) {
    cJSON *json = NULL;
    if (load_json(json_path, &json) != 0) {
        return 1;
    }

    int id = 1;
    if (cJSON_IsArray(json)) {
        id = cJSON_GetArraySize(json) + 1;
    }

    cJSON_Delete(json);
    return id;
}

int add_rule_to_map(struct rule *r) {
    int map_fd = bpf_obj_get(RULES_MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get rules_map");
        return -1;
    }


    uint32_t key = r->id;
    enum action act = r->action;

    if (bpf_map_update_elem(map_fd, &key, &act, BPF_ANY) != 0) {
        perror("bpf_map_update_elem rules_map");
        close(map_fd);
        return -1;
    }

    close(map_fd);
    return 0;
}

int remove_rule_from_map(uint32_t id) {
    int map_fd = bpf_obj_get(RULES_MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get rules_map");
        return -1;
    }

    if (bpf_map_delete_elem(map_fd, &id) != 0) {
        perror("bpf_map_delete_elem rules_map");
        close(map_fd);
        return -1;
    }

    close(map_fd);

    cJSON *json = NULL;
    if (load_json(RULES_JSON_PATH, &json) != 0) {
        return -1;
    }

    int array_size = cJSON_GetArraySize(json);
    for (int i = 0; i < array_size; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        if (cJSON_GetObjectItem(item, "id")->valueint == id) {
            cJSON_DeleteItemFromArray(json, i);
            break;
        }
    }

    if (save_json(RULES_JSON_PATH, json) != 0) {
        cJSON_Delete(json);
        return -1;
    }

    cJSON_Delete(json);
    printf("Rule with ID %u removed successfully.\n", id);
    return 0;
}

int add_filter_to_map(struct filter *f) {
    int map_fd = bpf_obj_get(FILTERS_MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get filters_map");
        return -1;
    }

    uint32_t key = f->id;

    if (bpf_map_update_elem(map_fd, &key, f, BPF_ANY) != 0) {
        perror("bpf_map_update_elem filters_map");
        close(map_fd);
        return -1;
    }

    close(map_fd);
    return 0;
}

int remove_filter_from_map(uint32_t id) {
    int map_fd = bpf_obj_get(FILTERS_MAP_PATH);
    if (map_fd < 0) {
        perror("bpf_obj_get filters_map");
        return -1;
    }

    if (bpf_map_delete_elem(map_fd, &id) != 0) {
        perror("bpf_map_delete_elem filters_map");
        close(map_fd);
        return -1;
    }

    close(map_fd);

    cJSON *json = NULL;
    if (load_json(FILTERS_JSON_PATH, &json) != 0) {
        return -1;
    }

    int array_size = cJSON_GetArraySize(json);
    for (int i = 0; i < array_size; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        if (cJSON_GetObjectItem(item, "id")->valueint == id) {
            cJSON_DeleteItemFromArray(json, i);
            break;
        }
    }

    if (save_json(FILTERS_JSON_PATH, json) != 0) {
        cJSON_Delete(json);
        return -1;
    }

    cJSON_Delete(json);
    printf("Filter with ID %u removed successfully.\n", id);
    return 0;
}

int start_firewall(const char *iface) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "sudo ip link set dev %s xdp obj xdp_firewall.o sec xdp", iface);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Failed to load XDP program on interface %s\n", iface);
        return -1;
    }
    printf("Firewall started on interface %s\n", iface);
    return 0;
}

int stop_firewall(const char *iface) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "sudo ip link set dev %s xdp off", iface);
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Failed to unload XDP program from interface %s\n", iface);
        return -1;
    }
    printf("Firewall stopped on interface %s\n", iface);
    return 0;
}

// CLI for adding a rule
int add_rule_cli(int argc, char **argv) {
    // Expected arguments after "add-rule"
    // srcip (<src_ip>/<mask>) dstip (<dst_ip>/<mask>) protocol (<UDP,TCP etc.>) contain (<DATA>) action (<drop/accept>)
    if (argc != 11) {
        fprintf(stderr, "Usage: %s add-rule srcip <src_ip>/<mask> dstip <dst_ip>/<mask> protocol <PROTO> contain <DATA> action <drop/accept>\n", argv[0]);
        return -1;
    }

    struct rule r = {};
    char src_ip_str[32], dst_ip_str[32], protocol_str[8], contain_str[32], action_str[8];
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "srcip") == 0 && i + 1 < argc) {
            strncpy(src_ip_str, argv[++i], sizeof(src_ip_str)-1);
        }
        else if (strcmp(argv[i], "dstip") == 0 && i + 1 < argc) {
            strncpy(dst_ip_str, argv[++i], sizeof(dst_ip_str)-1);
        }
        else if (strcmp(argv[i], "protocol") == 0 && i + 1 < argc) {
            strncpy(protocol_str, argv[++i], sizeof(protocol_str)-1);
        }
        else if (strcmp(argv[i], "contain") == 0 && i + 1 < argc) {
            strncpy(contain_str, argv[++i], sizeof(contain_str)-1);
        }
        else if (strcmp(argv[i], "action") == 0 && i + 1 < argc) {
            strncpy(action_str, argv[++i], sizeof(action_str)-1);
        }
    }

    char *slash = strchr(src_ip_str, '/');
    if (slash) {
        *slash = '\0';
        r.src_mask = atoi(slash + 1);
    }
    else {
        r.src_mask = 32;
    }
    if (inet_pton(AF_INET, src_ip_str, &r.src_ip) != 1) {
        fprintf(stderr, "Invalid source IP address: %s\n", src_ip_str);
        return -1;
    }

    slash = strchr(dst_ip_str, '/');
    if (slash) {
        *slash = '\0';
        r.dst_mask = atoi(slash + 1);
    }
    else {
        r.dst_mask = 32;
    }
    if (inet_pton(AF_INET, dst_ip_str, &r.dst_ip) != 1) {
        fprintf(stderr, "Invalid destination IP address: %s\n", dst_ip_str);
        return -1;
    }

    if (strcmp(protocol_str, "UDP") == 0)
        r.protocol = IPPROTO_UDP;
    else if (strcmp(protocol_str, "TCP") == 0)
        r.protocol = IPPROTO_TCP;
    else {
        fprintf(stderr, "Unsupported protocol: %s\n", protocol_str);
        return -1;
    }

    if (strcmp(action_str, "drop") == 0)
        r.action = ACTION_DROP;
    else if (strcmp(action_str, "accept") == 0)
        r.action = ACTION_ACCEPT;
    else {
        fprintf(stderr, "Unsupported action: %s\n", action_str);
        return -1;
    }

    strncpy(r.contain, contain_str, sizeof(r.contain)-1);

    r.id = generate_unique_id(RULES_JSON_PATH);

    if (add_rule_to_map(&r) != 0) {
        fprintf(stderr, "Failed to add rule to BPF map.\n");
        return -1;
    }

    cJSON *json = NULL;
    if (load_json(RULES_JSON_PATH, &json) != 0) {
        return -1;
    }

    cJSON *rule_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(rule_json, "id", r.id);
    cJSON_AddStringToObject(rule_json, "src_ip", src_ip_str);
    cJSON_AddNumberToObject(rule_json, "src_mask", r.src_mask);
    cJSON_AddStringToObject(rule_json, "dst_ip", dst_ip_str);
    cJSON_AddNumberToObject(rule_json, "dst_mask", r.dst_mask);
    cJSON_AddStringToObject(rule_json, "protocol", protocol_str);
    cJSON_AddStringToObject(rule_json, "contain", contain_str);
    cJSON_AddStringToObject(rule_json, "action", action_str);

    cJSON_AddItemToArray(json, rule_json);

    if (save_json(RULES_JSON_PATH, json) != 0) {
        cJSON_Delete(json);
        return -1;
    }

    cJSON_Delete(json);
    printf("Rule added successfully with ID %u.\n", r.id);
    return 0;
}

int add_filter_cli(int argc, char **argv) {

    if (argc != 6) {
        fprintf(stderr, "Usage: %s addfilter filtername <name> dstip <dst_ip>/<mask> port <port>\n", argv[0]);
        return -1;
    }

    struct filter f = {};
    char filtername[32], dst_ip_str[32];
    uint16_t port;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "filtername") == 0 && i + 1 < argc) {
            strncpy(filtername, argv[++i], sizeof(filtername)-1);
        }
        else if (strcmp(argv[i], "dstip") == 0 && i + 1 < argc) {
            strncpy(dst_ip_str, argv[++i], sizeof(dst_ip_str)-1);
        }
        else if (strcmp(argv[i], "port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        }
    }

    char *slash = strchr(dst_ip_str, '/');
    if (slash) {
        *slash = '\0';
        f.dst_mask = atoi(slash + 1);
    }
    else {
        f.dst_mask = 32;
    }
    if (inet_pton(AF_INET, dst_ip_str, &f.dst_ip) != 1) {
        fprintf(stderr, "Invalid destination IP address: %s\n", dst_ip_str);
        return -1;
    }

    strncpy(f.filtername, filtername, sizeof(f.filtername)-1);
    f.port = port;

    // Generate unique ID
    f.id = generate_unique_id(FILTERS_JSON_PATH);

    // Add filter to BPF map
    if (add_filter_to_map(&f) != 0) {
        fprintf(stderr, "Failed to add filter to BPF map.\n");
        return -1;
    }

    // Update JSON
    cJSON *json = NULL;
    if (load_json(FILTERS_JSON_PATH, &json) != 0) {
        return -1;
    }

    cJSON *filter_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(filter_json, "id", f.id);
    cJSON_AddStringToObject(filter_json, "filtername", filtername);
    cJSON_AddStringToObject(filter_json, "dst_ip", dst_ip_str);
    cJSON_AddNumberToObject(filter_json, "dst_mask", f.dst_mask);
    cJSON_AddNumberToObject(filter_json, "port", f.port);

    cJSON_AddItemToArray(json, filter_json);

    if (save_json(FILTERS_JSON_PATH, json) != 0) {
        cJSON_Delete(json);
        return -1;
    }

    cJSON_Delete(json);
    printf("Filter added successfully with ID %u.\n", f.id);
    return 0;
}
