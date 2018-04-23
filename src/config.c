/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2012-2018 Cuckoo Foundation.

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
#include "config.h"
#include "hooking.h"
#include "misc.h"
#include "native.h"
#include "ntapi.h"
#include "utf8.h"

static uint32_t _parse_mode(const char *mode)
{
    uint32_t ret = HOOK_MODE_ALL;
    while (*mode != 0) {
        if(*mode == ' ' || *mode == ',') {
            mode++;
            continue;
        }

        if(*mode >= '0' && *mode <= '9') {
            ret = strtoul(mode, NULL, 10);
            break;
        }

        if(strnicmp(mode, "dumptls", 7) == 0) {
            ret |= HOOK_MODE_DUMPTLS;
            mode += 7;
            continue;
        }

        if(strnicmp(mode, "iexplore", 8) == 0) {
            ret |= HOOK_MODE_BROWSER;
            mode += 8;
            continue;
        }

        if(strnicmp(mode, "office", 6) == 0) {
            ret |= HOOK_MODE_OFFICE | HOOK_MODE_EXPLOIT;
            mode += 6;
            continue;
        }

        if(strnicmp(mode, "pdf", 3) == 0) {
            ret |= HOOK_MODE_PDF | HOOK_MODE_EXPLOIT;
            mode += 3;
            continue;
        }

        if(strnicmp(mode, "exploit", 7) == 0) {
            ret |= HOOK_MODE_EXPLOIT;
            mode += 7;
            continue;
        }

        // Report.. find a more proper way? At this point the pipe has not
        // yet been initialized, so.
        message_box(NULL, "Invalid Monitor Mode", mode, 0);
    }
    return ret;
}

void config_read(config_t *cfg)
{
    char buf[512], config_fname[MAX_PATH];
    sprintf(config_fname, "C:\\cuckoo_%lu.ini", GetCurrentProcessId());

    memset(cfg, 0, sizeof(config_t));

    FILE *fp = fopen(config_fname, "rb");
    if(fp == NULL) {
        message_box(NULL, "Error fetching configuration file! This is a "
            "serious error. If encountered, please notify the Cuckoo "
            "Developers as this error prevents analysis.", "Cuckoo Error", 0);
        return;
    }

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
            strncpy(cfg->pipe_name, value, sizeof(cfg->pipe_name));
        }
        else if(strcmp(key, "logpipe") == 0) {
            strncpy(cfg->logpipe, value, sizeof(cfg->logpipe));
        }
        else if(strcmp(key, "shutdown-mutex") == 0) {
            strncpy(cfg->shutdown_mutex, value, sizeof(cfg->shutdown_mutex));
        }
        else if(strcmp(key, "first-process") == 0) {
            cfg->first_process = value[0] == '1';
        }
        else if(strcmp(key, "startup-time") == 0) {
            cfg->startup_time = strtoul(value, NULL, 10);
        }
        else if(strcmp(key, "force-sleepskip") == 0) {
            cfg->force_sleep_skip = value[0] == '1';
        }
        else if(strcmp(key, "hashes-path") == 0) {
            strncpy(cfg->hashes_path, value, sizeof(cfg->hashes_path));
        }
        else if(strcmp(key, "diffing-enable") == 0) {
            cfg->diffing_enable = value[0] == '1';
        }
        else if(strcmp(key, "track") == 0) {
            cfg->track = value[0] == '1';
        }
        else if(strcmp(key, "mode") == 0) {
            cfg->mode = _parse_mode(value);
        }
        else if(strcmp(key, "disguise") == 0) {
            cfg->disguise = value[0] == '1';
        }
        else if(strcmp(key, "pipe-pid") == 0) {
            cfg->pipe_pid = value[0] == '1';
        }
        else if(strcmp(key, "trigger") == 0) {
            utf8_decode_strn(
                value, cfg->trigger, sizeof(cfg->trigger) / sizeof(wchar_t)
            );
        }
    }
    fclose(fp);
    DeleteFile(config_fname);
}
