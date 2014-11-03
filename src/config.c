/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2014 Cuckoo Foundation.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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

            if(strcmp(key, "pipe") == 0) {
                strcpy(cfg->pipe_name, value);
            }
            else if(strcmp(key, "shutdown-mutex") == 0) {
                strcpy(cfg->shutdown_mutex, value);
            }
            else if(strcmp(key, "first-process") == 0) {
                cfg->first_process = value[0] == '1';
            }
            else if(strcmp(key, "startup-time") == 0) {
                cfg->startup_time = atoi(value);
            }
            else if(strcmp(key, "host-ip") == 0) {
                cfg->host_ip = inet_addr(value);
            }
            else if(strcmp(key, "host-port") == 0) {
                cfg->host_port = atoi(value);
            }
            else if(strcmp(key, "force-sleepskip") == 0) {
                cfg->force_sleep_skip = value[0] == '1';
            }
            else if(strcmp(key, "hashes-path") == 0) {
                strcpy(cfg->hashes_path, value);
            }
        }
        fclose(fp);
        DeleteFile(config_fname);
    }
}
