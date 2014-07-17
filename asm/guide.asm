global _asm_guide
global _asm_guide_size
global _asm_guide_orig_stub_off
global _asm_guide_eax_add_off

%define TLS_HOOK_INFO 0x44
%define TLS_LASTERR 0x34

%define LASTERR_OFF 4

asm_guide:

    push eax

    call _guide_addresses

_guide_orig_stub:
    dd 0x11223344

_guide_eax_add:
    dd 0x55667788

; _guide_eax_pop:
    ; dd 0x99aabbcc

_guide_addresses:
    pop eax

    ; temporarily store the original value of eax
    pushad
    push dword [esp+32]
    call dword [eax+_guide_eax_add-_guide_addresses]
    popad

    ; store the function table pointer
    mov dword [esp], eax

    ; restore the last error
    mov eax, dword [fs:TLS_HOOK_INFO]
    mov eax, dword [eax+LASTERR_OFF]
    mov dword [fs:TLS_LASTERR], eax

    ; fetch our return address
    mov eax, dword [esp]
    add eax, _guide_next - _guide_addresses

    ; spoof the return address
    mov dword [esp+4], eax

    ; fetch the original address
    call _guide_getpc

_guide_getpc:
    pop eax
    mov eax, dword [eax+_guide_orig_stub-_guide_getpc]

    ; jump to the original function stub
    mov dword [esp], eax
    retn

_guide_next:
    push eax

    ; save last error
    mov eax, dword [fs:TLS_HOOK_INFO]
    push dword [fs:TLS_LASTERR]
    pop dword [eax+LASTERR_OFF]

    pop eax
    retn

_guide_end:


_asm_guide dd asm_guide
_asm_guide_size dd _guide_end - asm_guide
_asm_guide_orig_stub_off dd _guide_orig_stub - asm_guide
_asm_guide_eax_add_off dd _guide_eax_add - asm_guide
