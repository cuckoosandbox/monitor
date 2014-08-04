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

global _asm_clean
global _asm_clean_size
global _asm_clean_retaddr_pop_off

%define TLS_HOOK_INFO 0x44
%define TLS_TEMPORARY 0x48
%define TLS_LASTERR 0x34

%define HOOKCNT_OFF 0
%define LASTERR_OFF 4

asm_clean:

    push eax

    ; restore last error
    mov eax, dword [fs:TLS_HOOK_INFO]
    push dword [eax+LASTERR_OFF]
    pop dword [fs:TLS_LASTERR]

    ; decrease hook count
    dec dword [eax+HOOKCNT_OFF]

    ; restore return address
    call _clean_getpc_target

_clean_getpc:
_clean_retaddr_pop:
    dd 0xcccccccc

_clean_getpc_target:
    pop eax

    ; restore original return address
    pushad
    call [eax+_clean_retaddr_pop-_clean_getpc]
    mov dword [fs:TLS_TEMPORARY], eax
    popad

    pop eax
    jmp dword [fs:TLS_TEMPORARY]

_clean_end:


_asm_clean dd asm_clean
_asm_clean_size dd _clean_end - asm_clean
_asm_clean_retaddr_pop_off dd _clean_retaddr_pop - asm_clean
