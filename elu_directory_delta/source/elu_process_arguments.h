/*
	UTF-8 process argument querying implementation authored by archiver Sakari N.

	Description

		The argument querying is implemented as a single function (elu_get_process_arguments).
		This function queries the process command line from Windows using GetCommandLineW and
		parses it in the same manner as CommandLineToArgvW without calling CommandLineToArgvW.
		The argument strings are converted to UTF-8 from Windows native "wide characters".
		This function does only depend on kernel32.dll.
		It is pretty much impossible to do any better on dependencies with Windows than this.
		The function returns a POSIX error code. The code is zero on success.

		The parameter "argument_count_address" is pointer to variable that will receive number of arguments.

		The parameter "argument_length_table_address" is pointer to variable that will receive address of first elements in the length argument table.

		The parameter "argument_table_address" is pointer to variable that will receive address of first elements in the argument table
		(i.e. the beginning of the argument string pointer table).
		The table has one extra element with value of zero at the end at after all arguments for making this more compatible with the c main function.
		If the function fails, no memory block is allocated.

		The argument table, length table and the strings are allocated in single block of memory.
		The argument string pointer table is at the beginning of this block and
		the value written (on successful call) to the variable pointed by parameter "argument_table_address" is
		the address of the first byte in this block.
		This block can be freed using VirtualFree with type MEM_RELEASE.
		Note that with MEM_RELEASE type VirtualFree size must be zero.
		This block is places in read only memory (virtual page protection PAGE_READONLY).

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

#ifndef ELU_PROCESS_ARGUMENTS_H
#define ELU_PROCESS_ARGUMENTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
	
int elu_get_process_arguments(size_t* argument_count_address, size_t** argument_length_table_address, char*** argument_table_address);

#ifdef __cplusplus
}
#endif

#endif // ELU_PROCESS_ARGUMENTS_H