global _asm_clean
global _asm_clean_size

%define TLS_HOOK_INFO 0x44
%define TLS_LASTERR 0x34

%define HOOKCNT_OFF 0
%define LASTERR_OFF 4

_asm_clean:

    push eax

    ; restore last error
    mov eax, dword [fs:TLS_HOOK_INFO]
    push dword [eax+LASTERR_OFF]
    pop dword [fs:TLS_LASTERR]

    ; decrease hook count
    dec dword [eax+HOOKCNT_OFF]

    ; restore return address
    call _clean_getpc

_clean_retaddr_pop:
    dd 0x11223344

_clean_getpc:
    pop eax

    ; fetch return address
    call [eax+_clean_retaddr_pop-_clean_getpc]

    ; restore original return address
    mov dword [esp+4], eax

    pop eax
    retn

_clean_end:


_asm_clean_size dd _clean_end - _asm_clean
