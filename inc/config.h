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

#ifndef MONITOR_CONFIG_H
#define MONITOR_CONFIG_H

#include <stdint.h>
#include <windows.h>

typedef struct _config_t {
    // Pipe name to communicate with Cuckoo.
    char pipe_name[MAX_PATH];

    // Log pipe name to write bson logs to.
    char logpipe[MAX_PATH];

    // If this mutex exists then the Virtual Machine is shutting down.
    char shutdown_mutex[MAX_PATH];

    // Whether this is the first process.
    int first_process;

    // Randomized amount of milliseconds since startup.
    uint32_t startup_time;
    uint32_t force_sleep_skip;

    // Path to non-interesting hashes.
    char hashes_path[MAX_PATH];

    // Enable diffing logging - this is disabled by default.
    int diffing_enable;

    // Whether this pid should be monitored for in the analyzer.
    int track;

    // Monitoring mode.
    int mode;

    // Disguise the VM in an attempt to fool samples into thinking it's a
    // real machine?
    int disguise;

    // If we should prepend each pipe message with our pid (requires the
    // latest version on the Analyzer side).
    int pipe_pid;

    // Dynamic triggers that start the logging for this analysis.
    wchar_t trigger[MAX_PATH+16];
} config_t;

void config_read(config_t *cfg);

#endif
