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

%include "misc.inc"

global asm_guide
global asm_guide_size
global asm_guide_orig_stub_off
global asm_guide_retaddr_add_off
global asm_guide_retaddr_pop_off

%define TLS_HOOK_INFO 0x80
%define TLS_TEMPORARY 0x88
%define TLS_TEB       0x30
%define TEB_LASTERR   0x68

%define LASTERR_OFF 8

_asm_guide:

    ; restore the last error
    push rbx
    mov rax, qword [gs:TLS_HOOK_INFO]
    mov rbx, qword [gs:TLS_TEB]
    mov eax, dword [rax+LASTERR_OFF]
    mov dword [rbx+TEB_LASTERR], eax
    pop rbx

    call _guide_getpc_target

_guide_getpc:

align 8

_guide_orig_stub:
    dq 0xcccccccccccccccc

_guide_retaddr_add:
    dq 0xcccccccccccccccc

_guide_retaddr_pop:
    dq 0xcccccccccccccccc

_guide_getpc_target:
    pop rax

    ; temporarily store the original return address
    pushad
    mov rcx, qword [rsp+128]
    call qword [rax+_guide_retaddr_add-_guide_getpc]
    popad

    ; fetch our return address
    add rax, _guide_next - _guide_getpc

    ; spoof the return address
    mov qword [rsp], rax

    ; jump to the original function stub
    jmp qword [rax+_guide_orig_stub-_guide_next]

_guide_next:
    push rax

    ; save last error
    push rbx
    mov rax, qword [gs:TLS_HOOK_INFO]
    mov rbx, qword [gs:TLS_TEB]
    mov ebx, dword [rbx+TEB_LASTERR]
    mov dword [rax+LASTERR_OFF], ebx
    pop rbx

    call _guide_getpc2

_guide_getpc2:
    pop rax

    ; pop the original return address
    pushad
    call qword [rax+_guide_retaddr_pop-_guide_getpc2]
    mov qword [gs:TLS_TEMPORARY], rax
    popad

    pop rax
    jmp qword [gs:TLS_TEMPORARY]

_guide_end:


asm_guide dq _asm_guide
asm_guide_size dd _guide_end - _asm_guide
asm_guide_orig_stub_off dd _guide_orig_stub - _asm_guide
asm_guide_retaddr_add_off dd _guide_retaddr_add - _asm_guide
asm_guide_retaddr_pop_off dd _guide_retaddr_pop - _asm_guide
