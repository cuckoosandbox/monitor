; Cuckoo Sandbox - Automated Malware Analysis.
; Copyright (C) 2010-2014 Cuckoo Foundation.
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

%include "misc.asm"

global asm_clean
global asm_clean_size
global asm_clean_retaddr_pop_off

%define TLS_HOOK_INFO 0x80
%define TLS_TEMPORARY 0x88
%define TLS_LASTERR 0x34

%define HOOKCNT_OFF 0
%define LASTERR_OFF 8

_asm_clean:

    push rax

    ; restore last error
    mov rax, qword [gs:TLS_HOOK_INFO]
    push qword [rax+LASTERR_OFF]
    pop qword [gs:TLS_LASTERR]

    ; decrease hook count
    dec qword [rax+HOOKCNT_OFF]

    ; restore return address
    call _clean_getpc_target

_clean_getpc:
_clean_retaddr_pop:
    dq 0xcccccccccccccccc

_clean_getpc_target:
    pop rax

    ; restore original return address
    pushad
    call [rax+_clean_retaddr_pop-_clean_getpc]
    mov qword [gs:TLS_TEMPORARY], rax
    popad

    pop rax
    jmp qword [gs:TLS_TEMPORARY]

_clean_end:


asm_clean dq _asm_clean
asm_clean_size dd _clean_end - _asm_clean
asm_clean_retaddr_pop_off dd _clean_retaddr_pop - _asm_clean
