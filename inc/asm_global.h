#ifndef MONITOR_ASMGLOBAL_H
#define MONITOR_ASMGLOBAL_H

#include <stdint.h>

extern const uint8_t *asm_tramp;
extern const uint32_t asm_tramp_size;
extern const uint32_t asm_tramp_hook_alloc_off;
extern const uint32_t asm_tramp_hook_handler_off;
extern const uint32_t asm_tramp_orig_func_stub_off;
extern const uint32_t asm_tramp_retaddr_off;
extern const uint32_t asm_tramp_retaddr_add_off;

extern const uint8_t *asm_guide;
extern const uint32_t asm_guide_size;
extern const uint32_t asm_guide_orig_stub_off;
extern const uint32_t asm_guide_retaddr_add_off;
extern const uint32_t asm_guide_retaddr_pop_off;

extern const uint8_t *asm_clean;
extern const uint32_t asm_clean_size;
extern const uint32_t asm_clean_retaddr_pop_off;

#endif
