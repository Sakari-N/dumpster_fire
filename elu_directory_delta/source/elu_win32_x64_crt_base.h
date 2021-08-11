/*
	Implementations of base x64 C runtime library functions for Visual Studio authored by archiver Sakari N.

		Implementations for some on the base CRT functions.
		This exist for building C programs using Visual Studio without C runtime library.
		There are few dumb problems with Visual Studio when C runtime library is not used.
		One of these problems is implicit calls to some of the C runtime functions,
		because of this these functions may need to be implemented even if there are no
		references to these functions in the code. At Least functions memset and memcpy are commonly called.
		Another problem is code generated Visual Studio refers to variable named _fltused
		when any floating point operations are used.

	License

		This is free and unencumbered software released into the public domain.

		Anyone is free to copy, modify, publish, use, compile, sell, or
		distribute this software, either in source code form or as a compiled
		binary, for any purpose, commercial or non-commercial, and by any
		means.

		In jurisdictions that recognize copyright laws, the author or authors
		of this software dedicate any and all copyright interest in the
		software to the public domain. We make this dedication for the benefit
		of the public at large and to the detriment of our heirs and
		successors. We intend this dedication to be an overt act of
		relinquishment in perpetuity of all present and future rights to this
		software under copyright law.

		THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
		EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
		MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
		IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
		OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
		ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
		OTHER DEALINGS IN THE SOFTWARE.

		For more information, please refer to <https://unlicense.org>
*/

#ifndef ELU_WIN32_X64_CRT_BASE_H
#define ELU_WIN32_X64_CRT_BASE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable : 28251) // Allow redeclaration of names
#endif // _MSC_VER

#include <stddef.h>
#include <stdint.h>

extern int _fltused;
/*
	Do not ever access this variable.
	It might cause access violation, because it is placed in the .text segment to be less bloaty.
	The variable only exists to suppress Microsoft's stupidity.
*/

extern void* __cdecl memset(void* ptr, int value, size_t num);
extern void* __cdecl memcpy(void* destination, const void* source, size_t num);
extern int __cdecl memcmp(void const* ptr1, void const* ptr2, size_t num);
/*
	There is no point in documenting these functions for obvious reasons.

	The chkstk is also implemented for the linker, but not exported to C since it uses its own calling convention.
*/

#ifdef _MSC_VER
#pragma warning( pop )
#endif // _MSC_VER

#ifdef __cplusplus
}
#endif

#endif // ELU_WIN32_X64_CRT_BASE_H
