; Cuckoo Sandbox - Automated Malware Analysis.
; Copyright (C) 2010-2015 Cuckoo Foundation.
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http://www.gnu.org/licenses/>.

%ifndef tramp_special
global _asm_tramp
global _asm_tramp_size
global _asm_tramp_hook_handler_off
global _asm_tramp_orig_func_stub_off
global _asm_tramp_retaddr_off
global _asm_tramp_retaddr_add_off
%else
global _asm_tramp_special
global _asm_tramp_special_size
global _asm_tramp_special_hook_handler_off
global _asm_tramp_special_orig_func_stub_off
global _asm_tramp_special_retaddr_off
global _asm_tramp_special_retaddr_add_off
%endif

extern _hook_info_wrapper

%define TLS_LASTERR 0x34

%define HOOKCNT_OFF 0
%define LASTERR_OFF 4

asm_tramp:

    ; fetch hook-info
    call dword [_hook_info_wrapper]

    jmp _tramp_addresses

_tramp_hook_handler:
    dd 0xcccccccc

_tramp_orig_func_stub:
    dd 0xcccccccc

_tramp_retaddr:
    dd 0xcccccccc

_tramp_retaddr_add:
    dd 0xcccccccc

_tramp_addresses:

%ifndef tramp_special

    cmp dword [eax+HOOKCNT_OFF], 0
    jz _tramp_do_it

    ; we're already in a hook - abort
    call _tramp_getpc2

_tramp_getpc2:
    pop eax

    ; jump to the original function stub
    jmp dword [eax+_tramp_orig_func_stub-_tramp_getpc2]

%endif

_tramp_do_it:

    ; increase hook count
    inc dword [eax+HOOKCNT_OFF]

    ; save last error
    push dword [fs:TLS_LASTERR]
    pop dword [eax+LASTERR_OFF]

    call _tramp_getpc3

_tramp_getpc3:
    pop eax

    ; save the return address
    pushad
    push dword [esp+32]
    call dword [eax+_tramp_retaddr_add-_tramp_getpc3]
    popad

    ; fetch the new return address
    push dword [eax+_tramp_retaddr-_tramp_getpc3]

    ; actually patch the return address
    pop dword [esp]

    ; jump to the hook handler
    jmp dword [eax+_tramp_hook_handler-_tramp_getpc3]

_tramp_end:


%ifndef tramp_special
_asm_tramp dd asm_tramp
_asm_tramp_size dd _tramp_end - asm_tramp
_asm_tramp_hook_handler_off dd _tramp_hook_handler - asm_tramp
_asm_tramp_orig_func_stub_off dd _tramp_orig_func_stub - asm_tramp
_asm_tramp_retaddr_off dd _tramp_retaddr - asm_tramp
_asm_tramp_retaddr_add_off dd _tramp_retaddr_add - asm_tramp
%else
_asm_tramp_special dd asm_tramp
_asm_tramp_special_size dd _tramp_end - asm_tramp
_asm_tramp_special_hook_handler_off dd _tramp_hook_handler - asm_tramp
_asm_tramp_special_orig_func_stub_off dd _tramp_orig_func_stub - asm_tramp
_asm_tramp_special_retaddr_off dd _tramp_retaddr - asm_tramp
_asm_tramp_special_retaddr_add_off dd _tramp_retaddr_add - asm_tramp
%endif
