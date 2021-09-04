/*
	Memory API authored by archiver Sakari N.

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

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "elu_memory.h"
#include <Windows.h>

size_t elu_get_memory_page_size()
{
	SYSTEM_INFO system_info;
	GetSystemInfo(&system_info);
	size_t page_size = (size_t)system_info.dwPageSize;

	// assume that page size is power of two
#ifdef _DEBUG
	if ((page_size & (page_size - 1)) != 0)
		*((volatile int*)0) = 0;
#endif // _DEBUG
#ifdef _MSC_VER
	__assume(!(page_size & (page_size - 1)));
#endif // _MSC_VER

	return (size_t)system_info.dwPageSize;
}

int elu_allocate_memory(size_t size, void** memory_address)
{
	size_t page_size = elu_get_memory_page_size();
#ifdef _MSC_VER
	__assume(!(page_size & (page_size - 1)));
#endif // _MSC_VER
	size = (size + (page_size - 1)) & ~(page_size - 1);

	void* memory = VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!memory)
	{
		return ENOMEM;
	}

	*memory_address = memory;
	return 0;
}

int elu_free_memory(size_t size, void* memory)
{
	int error = VirtualFree(memory, 0, MEM_RELEASE) ? 0 : EINVAL;
	return error;
}

#ifdef __cplusplus
}
#endif // __cplusplus
