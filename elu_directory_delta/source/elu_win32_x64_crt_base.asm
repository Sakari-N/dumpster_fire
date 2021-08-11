; Implementations of base x64 C runtime library functions for Visual Studio authored by archiver Sakari N.
;
; License
;
;	This is free and unencumbered software released into the public domain.
; 
;	Anyone is free to copy, modify, publish, use, compile, sell, or
;	distribute this software, either in source code form or as a compiled
;	binary, for any purpose, commercial or non-commercial, and by any
;	means.
; 
;	In jurisdictions that recognize copyright laws, the author or authors
;	of this software dedicate any and all copyright interest in the
;	software to the public domain. We make this dedication for the benefit
;	of the public at large and to the detriment of our heirs and
;	successors. We intend this dedication to be an overt act of
;	relinquishment in perpetuity of all present and future rights to this
;	software under copyright law.
; 
;	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
;	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
;	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
;	IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
;	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
;	ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
;	OTHER DEALINGS IN THE SOFTWARE.
; 
;	For more information, please refer to <https://unlicense.org>

.CODE

PUBLIC _fltused
_fltused dd 0H

PUBLIC __chkstk
__chkstk PROC
; The size located in rax, so the standard calling convention is not used for this function
push rax
push rcx  
;rcx = rsp - ((rax + (8192 - 1)) & ~(8192 - 1))
mov rcx,01FFFH
add rax,rcx
not rcx
and rax,rcx
mov rcx,rsp
sub rcx,rax
;OK. This is just some Windows stuff here. The lowest stack page address is located in gs:[010H]
;So the page probing can be skipped if the lowest page is below rsp + size
mov rax,QWORD PTR gs:[010H]
cmp rcx,rax
jae __chkstk_exit
mov rax,rsp
;loop while rax != rcx
jmp __chkstk_loop_compare
__chkstk_loop_process:
sub rax,01000H
mov BYTE PTR [rax],0H
__chkstk_loop_compare:
cmp rcx,rax
jne __chkstk_loop_process
__chkstk_exit:
pop rcx
pop rax
ret
__chkstk ENDP

PUBLIC memset
memset PROC
; rcx = ptr, rdx = value, r8 = num
mov r10, rdi
mov rax, rdx
mov r9, rcx
mov rdi, rcx
mov rcx, r8
cld
rep stosb [rdi]
mov rdi, r10; restore contents of rdi
mov rax, r9; set return value to ptr parameter
ret
memset ENDP

PUBLIC memcpy
memcpy PROC
; rcx = destination, rdx = source, r8 = num
mov r9, rdi
mov r10, rsi
mov rax, rcx; set return value to destination parameter
mov rsi, rdx
mov rdi, rcx
mov rcx, r8
cld
rep movsb [rdi], [rsi]
mov rdi, r9; restore contents of rdi and rsi
mov rsi, r10;
ret
memcpy ENDP

PUBLIC memcmp
memcmp PROC
; rcx = ptr1, rdx = ptr2, r8 = num
mov r9, rdi
mov rax, rsi
mov rsi, rcx
mov rdi, rdx
mov rcx, r8
cld
repe cmpsb
mov rdi, r9
mov rsi, rax
jne memcmp_mismatch
xor rax, rax
ret
memcmp_mismatch:
sbb rax, rax
or rax, 1H
ret
memcmp ENDP

END