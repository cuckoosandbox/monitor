#ifndef MONITOR_UNHOOK_H
#define MONITOR_UNHOOK_H

#include <stdint.h>

void unhook_detect_add_region(const char *funcname, const uint8_t *addr,
    const uint8_t *orig, const uint8_t *our, uint32_t length);

int unhook_init_detection();

#endif
