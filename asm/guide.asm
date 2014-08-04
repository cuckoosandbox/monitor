global _asm_guide
global _asm_guide_size
global _asm_guide_orig_stub_off
global _asm_guide_retaddr_add_off
global _asm_guide_retaddr_pop_off

%define TLS_HOOK_INFO 0x44
%define TLS_TEMPORARY 0x48
%define TLS_LASTERR 0x34

%define LASTERR_OFF 4

asm_guide:

    ; restore the last error
    mov eax, dword [fs:TLS_HOOK_INFO]
    mov eax, dword [eax+LASTERR_OFF]
    mov dword [fs:TLS_LASTERR], eax

    call _guide_getpc_target

_guide_getpc:
_guide_orig_stub:
    dd 0xcccccccc

_guide_retaddr_add:
    dd 0xcccccccc

_guide_retaddr_pop:
    dd 0xcccccccc

_guide_getpc_target:
    pop eax

    ; temporarily store the original return address
    pushad
    push dword [esp+32]
    call dword [eax+_guide_retaddr_add-_guide_getpc]
    popad

    ; fetch our return address
    add eax, _guide_next - _guide_getpc

    ; spoof the return address
    mov dword [esp], eax

    ; jump to the original function stub
    jmp dword [eax+_guide_orig_stub-_guide_next]

_guide_next:
    push eax

    ; save last error
    mov eax, dword [fs:TLS_HOOK_INFO]
    push dword [fs:TLS_LASTERR]
    pop dword [eax+LASTERR_OFF]

    call _guide_getpc2

_guide_getpc2:
    pop eax

    ; pop the original return address
    pushad
    call dword [eax+_guide_retaddr_pop-_guide_getpc2]
    mov dword [fs:TLS_TEMPORARY], eax
    popad

    pop eax
    jmp dword [fs:TLS_TEMPORARY]

_guide_end:


_asm_guide dd asm_guide
_asm_guide_size dd _guide_end - asm_guide
_asm_guide_orig_stub_off dd _guide_orig_stub - asm_guide
_asm_guide_retaddr_add_off dd _guide_retaddr_add - asm_guide
_asm_guide_retaddr_pop_off dd _guide_retaddr_pop - asm_guide
