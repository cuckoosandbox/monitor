#ifndef MONITOR_CONFIG_H
#define MONITOR_CONFIG_H

#include <stdint.h>
#include <windows.h>

typedef struct _config_t {
    // Pipe name to communicate with Cuckoo.
    char pipe_name[MAX_PATH];

    // If this mutex exists then we're shutting down.
    char shutdown_mutex[MAX_PATH];

    // Whether this is the first process.
    int first_process;

    // Randomized amount of milliseconds since startup.
    uint32_t startup_time;

    // Server ip and port.
    uint32_t host_ip;
    uint16_t host_port;
} config_t;

void config_read(config_t *cfg);

#endif
