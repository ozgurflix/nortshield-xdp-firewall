#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common.h"
#include "log_manager.h"

#define LOG_FILE "data/logs.json"

typedef struct {
    time_t timestamp;
    char message[256];
} LogEntry;

void write_log(const char *message) {
    FILE *file = fopen(LOG_FILE, "a");
    if (file == NULL) {
        perror("Could not open log file");
        return;
    }

    LogEntry entry;
    entry.timestamp = time(NULL);
    strncpy(entry.message, message, sizeof(entry.message) - 1);
    entry.message[sizeof(entry.message) - 1] = '\0';

    fprintf(file, "{\"timestamp\": %ld, \"message\": \"%s\"}\n", entry.timestamp, entry.message);
    fclose(file);
}

void log_manager() {
    FILE *file = fopen(LOG_FILE, "r");
    if (file == NULL) {
        perror("Could not open log file");
        return;
    }

    char line[512];
    printf("Logs:\n");
    while (fgets(line, sizeof(line), file) != NULL) {
        printf("%s", line);
    }

    fclose(file);
}
