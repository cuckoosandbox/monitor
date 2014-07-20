#include <stdio.h>
#include <windows.h>
#include "ntapi.h"
#include "config.h"

void config_read(config_t *cfg)
{
    char buf[512], config_fname[MAX_PATH];
    sprintf(config_fname, "%s\\%lu.ini",
        getenv("TEMP"), GetCurrentProcessId());

    memset(cfg, 0, sizeof(config_t));

    FILE *fp = fopen(config_fname, "rb");
    if(fp != NULL) {
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            // Cut off the newline.
            char *p = strchr(buf, '\r');
            if(p != NULL) *p = 0;

            p = strchr(buf, '\n');
            if(p != NULL) *p = 0;

            // Split key=value.
            p = strchr(buf, '=');
            if(p == NULL) continue;

            *p = 0;

            const char *key = buf, *value = p + 1;

            if(!strcmp(key, "pipe")) {
                strcpy(cfg->pipe_name, value);
            }
            else if(!strcmp(key, "shutdown-mutex")) {
                strcpy(cfg->shutdown_mutex, value);
            }
            else if(!strcmp(key, "first-process")) {
                cfg->first_process = value[0] == '1';
            }
            else if(!strcmp(key, "startup-time")) {
                cfg->startup_time = atoi(value);
            }
            else if(!strcmp(key, "host-ip")) {
                cfg->host_ip = inet_addr(value);
            }
            else if(!strcmp(key, "host-port")) {
                cfg->host_port = atoi(value);
            }
        }
        fclose(fp);
        DeleteFile(config_fname);
    }
}
