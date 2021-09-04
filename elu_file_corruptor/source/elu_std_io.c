/*
	Simple STD IO interface authored by archiver Sakari N.

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
#endif

#ifdef _MSC_VER
#pragma warning( push )

// _alloca
#pragma warning( disable : 6255)

// Large per function stack usage
#pragma warning( disable : 6262)

#endif

#include "elu_std_io.h"
#include <Windows.h>

int elu_read_std_io(size_t buffer_size, char* buffer)
{
	return ENOTSUP;

	/*
	HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
	if (!handle || handle == INVALID_HANDLE_VALUE)
		return ENOSYS;

	ReadConsoleW(handle, 

	return 0;
	*/
}

int elu_write_std_io(size_t size, const char* data)
{
#define LOCAL_MAX_CHARACTERS_PER_WRITE 0x8000

	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (!handle || handle == INVALID_HANDLE_VALUE)
		return ENOSYS;

	if (!size)
		return 0;

	int first_write_failed = 0;
	WCHAR buffer[LOCAL_MAX_CHARACTERS_PER_WRITE];
	DWORD write_length;
	for (size_t i = 0; !first_write_failed && i != size;)
	{
		int read_size = ((size - i) < LOCAL_MAX_CHARACTERS_PER_WRITE) ? (int)(size - i) : (int)LOCAL_MAX_CHARACTERS_PER_WRITE;
		for (int adjustment_limit = 4; adjustment_limit && read_size > 2 && (*(unsigned char*)(data + i + read_size - 1) > 0x7F); --adjustment_limit)
			--read_size;

		int write_request_length = MultiByteToWideChar(CP_UTF8, 0, data + i, read_size, buffer, LOCAL_MAX_CHARACTERS_PER_WRITE);
		if (!write_request_length)
			return EIO;

		for (int j = 0; !first_write_failed && j != write_request_length;)
		{
			BOOL write_result = WriteConsoleW(handle, (const void*)(buffer + j), (DWORD)(write_request_length - j), &write_length, 0);
			if (write_result && write_length)
				j += (int)write_length;
			else
				first_write_failed = 1;
		}

		i += (size_t)read_size;
	}

	if (first_write_failed)
	{
		// write for non console output.
		for (size_t i = 0; i != size;)
		{
			DWORD transfer_size = (((size - i) < (size_t)0x80000000) ? (DWORD)(size - i) : (DWORD)0x80000000);
			BOOL write_result = WriteFile(handle, (const void*)((uintptr_t)data + i), transfer_size, &write_length, 0);
			if (write_result && write_length)
				i += (size_t)write_length;
			else
				return EIO;
		}
	}

	return 0;
#undef LOCAL_MAX_CHARACTERS_PER_WRITE
}

#ifdef _MSC_VER
#pragma warning( pop )
#endif // _MSC_VER

#ifdef __cplusplus
}
#endif
