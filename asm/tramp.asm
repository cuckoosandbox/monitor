global _asm_tramp
global _asm_tramp_size
global _asm_tramp_hook_alloc_off
global _asm_tramp_orig_func_stub_off
global _asm_tramp_retaddr_off
global _asm_tramp_retaddr_add_off

%define TLS_HOOK_INFO 0x44
%define TLS_LASTERR 0x34

%define HOOKCNT_OFF 0
%define LASTERR_OFF 4
%define HANDLER_OFF 8

asm_tramp:

    ; fetch hook-info
    mov eax, dword [fs:TLS_HOOK_INFO]
    jmp _tramp_addresses

_tramp_hook_alloc:
    dd 0xffeeddcc

_tramp_orig_func_stub:
    dd 0x11223344

_tramp_retaddr:
    dd 0x55667788

_tramp_retaddr_add:
    dd 0x99aabbcc

_tramp_addresses:

    test eax, eax
    jnz _tramp_check_count

    ; create hook-info
    call _tramp_getpc3

_tramp_getpc3:
    pop eax

    pushad
    call dword [eax+_tramp_hook_alloc-_tramp_getpc3]
    popad

    mov eax, dword [fs:TLS_HOOK_INFO]

_tramp_check_count:

%ifndef tramp_special

    cmp dword [eax+HOOKCNT_OFF], 0
    jz _tramp_do_it

    ; we're already in a hook - abort
    call _tramp_getpc

_tramp_getpc:
    pop eax
    add eax, _tramp_orig_func_stub - _tramp_getpc

    ; jump to the original function stub
    jmp dword [eax]

%endif

_tramp_do_it:

    ; increase hook count
    inc dword [eax+HOOKCNT_OFF]

    ; save last error
    push dword [fs:TLS_LASTERR]
    pop dword [eax+LASTERR_OFF]

    call _tramp_getpc2

_tramp_getpc2:
    pop eax

    pushad

    ; save the return address
    push dword [esp+32]
    call dword [eax+_tramp_retaddr_add-_tramp_getpc2]

    popad

    ; fetch the new return address
    mov eax, [eax+_tramp_retaddr-_tramp_getpc2]

    ; actually patch the return address
    mov dword [esp], eax

    ; jump to the hook handler
    mov eax, dword [fs:TLS_HOOK_INFO]
    jmp dword [eax+HANDLER_OFF]

_tramp_end:


_asm_tramp dd asm_tramp
_asm_tramp_size dd _tramp_end - asm_tramp
_asm_tramp_hook_alloc_off dd _tramp_hook_alloc - asm_tramp
_asm_tramp_orig_func_stub_off dd _tramp_orig_func_stub - asm_tramp
_asm_tramp_retaddr_off dd _tramp_retaddr - asm_tramp
_asm_tramp_retaddr_add_off dd _tramp_retaddr_add - asm_tramp
