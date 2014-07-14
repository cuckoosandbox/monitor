global asm_guide
global asm_guide_size

%define TLS_HOOK_INFO 0x44
%define TLS_LASTERR 0x34

%define LASTERR_OFF 4

asm_guide:

    push eax

    call _guide_addresses

_guide_orig:
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
    mov eax, dword [eax+_guide_orig-_guide_getpc]

    ; jump to the original function
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


asm_guide_size dd $$ - asm_guide
