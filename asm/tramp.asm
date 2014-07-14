global asm_tramp
global asm_tramp_size
global asm_tramp_orig_func_off
global asm_tramp_retaddr_off

%define TLS_HOOK_INFO 0x44
%define TLS_LASTERR 0x34

%define HOOKCNT_OFF 0
%define LASTERR_OFF 4

asm_tramp:

    ; fetch hook-info
    push eax
    mov eax, dword [fs:TLS_HOOK_INFO]
    jmp _tramp_addresses

_tramp_orig_func:
    dd 0x11223344

_tramp_retaddr:
    dd 0x55667788

_tramp_retaddr_add:
    dd 0x99aabbcc

_tramp_addresses:

    ; test eax, eax
    ; jnz _tramp_check_count

    ; create hook-info
    ; pushad
    ; call hook_alloc
    ; popad
    ; mov eax, fs:[TLS_HOOK_INFO]

; _tramp_check_count:

%ifndef tramp_special

    cmp dword [eax+HOOKCNT_OFF], 0
    jle _tramp_do_it

    ; we're already in a hook - abort
    call _tramp_getpc

_tramp_getpc:
    pop eax
    add eax, _tramp_orig_func - _tramp_getpc

    ; jmp [eax] and restore eax at once
    xchg eax, dword [esp]
    retn

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

    push eax

    ; save the return address
    push dword [esp+8]
    call dword [eax+_tramp_retaddr_add-_tramp_getpc2]

    pop eax

    ; fetch the new return address
    mov eax, [eax+_tramp_retaddr-_tramp_getpc2]

    ; actually patch the return address
    xchg dword [esp+4], eax

_tramp_cleanup:
    pop eax


asm_tramp_size dd $$ - asm_tramp
asm_tramp_orig_func_off dd _tramp_orig_func - asm_tramp
asm_tramp_retaddr_off dd _tramp_retaddr - asm_tramp
