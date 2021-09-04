/*
	UTF-8 process argument querying implementation authored by archiver Sakari N.

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

#include "elu_process.h"
#include <Windows.h>

#ifdef _MSC_VER
#pragma warning( push )
// Buffer read/write overrun. The Microsoft C/C++ compiler is so wrong about these that it is not even funny
#pragma warning( disable : 6385 )
#pragma warning( disable : 6386 )
#endif // _MSC_VER

#if 1
#define SYS_EINVAL 22
#define SYS_ENOMEM 12
#define SYS_ENOENT 2
#define SYS_EIO 5
#else
#include <errno.h>
#define SYS_EINVAL EINVAL
#define SYS_ENOMEM ENOMEM
#define SYS_ENOENT ENOENT
#define SYS_EIO EIO
#endif

static int elu_native_command_line_to_arguments(const WCHAR* native_command, size_t* argument_count_address, size_t** argument_length_table_address, char*** argument_table_address, size_t* argument_table_size_address)
{
	const size_t max_file_name_length = 0x7FFF;
	const int int_max = (int)(((unsigned int)~0) >> 1);

	SYSTEM_INFO system_info;
	GetSystemInfo(&system_info);
	size_t page_size = system_info.dwPageSize ? (size_t)system_info.dwPageSize : 1;
#ifdef _MSC_VER
	// Assume that page size is power of two and fits in 32 bit value. Ths is 0x1000 anyway, but just in case of large pages or something this is not hardcoded
	__assume(!(page_size & (page_size - 1)));
#endif

	int native_command_length = 0;
	while (native_command[native_command_length])
	{
		++native_command_length;
		if (native_command_length == int_max)
			return SYS_EINVAL;
	}

	if (!native_command_length)
	{
		size_t utf16_executable_name_size = ((size_t)(MAX_PATH + 1) * sizeof(WCHAR));
#ifdef _MSC_VER
		__assume(((utf16_executable_name_size + (page_size - 1)) & ~(page_size - 1)) >= utf16_executable_name_size);
#endif
		utf16_executable_name_size = ((utf16_executable_name_size + (page_size - 1)) & ~(page_size - 1));
		WCHAR* utf16_executable_name = (WCHAR*)VirtualAlloc(0, utf16_executable_name_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!utf16_executable_name)
			return SYS_ENOMEM;

		size_t utf16_executable_name_length = (size_t)GetModuleFileNameW(0, utf16_executable_name, (DWORD)(utf16_executable_name_size / sizeof(WCHAR)));
		if (!utf16_executable_name_length || utf16_executable_name_length > (utf16_executable_name_size / sizeof(WCHAR)))
		{
			VirtualFree(utf16_executable_name, 0, MEM_RELEASE);
			utf16_executable_name_size = ((max_file_name_length + 1) * sizeof(WCHAR));
#ifdef _MSC_VER
			__assume(((utf16_executable_name_size + (page_size - 1)) & ~(page_size - 1)) >= utf16_executable_name_size);
#endif
			utf16_executable_name_size = ((utf16_executable_name_size + (page_size - 1)) & ~(page_size - 1));
			utf16_executable_name = (WCHAR*)VirtualAlloc(0, utf16_executable_name_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			if (!utf16_executable_name)
				return SYS_ENOMEM;

			utf16_executable_name_length = (size_t)GetModuleFileNameW(0, utf16_executable_name, (DWORD)(utf16_executable_name_size / sizeof(WCHAR)));
			if (!utf16_executable_name_length || utf16_executable_name_length > (utf16_executable_name_size / sizeof(WCHAR)))
			{
				VirtualFree(utf16_executable_name, 0, MEM_RELEASE);
				return SYS_ENOENT;
			}
		}

		int utf8_executable_name_length = WideCharToMultiByte(CP_UTF8, 0, utf16_executable_name, (int)utf16_executable_name_length, 0, 0, 0, 0);
		if (!utf8_executable_name_length)
			return SYS_EINVAL;

		size_t utf8_table_size = ((2 * sizeof(char*)) + (2 * sizeof(size_t)) + ((size_t)utf8_executable_name_length + 1));
#ifdef _MSC_VER
		__assume(((utf8_table_size + (page_size - 1)) & ~(page_size - 1)) >= utf8_table_size);
#endif
		utf8_table_size = ((utf8_table_size + (page_size - 1)) & ~(page_size - 1));
		char** utf8_table = (char**)VirtualAlloc(0, utf8_table_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!utf8_table)
		{
			VirtualFree(utf16_executable_name, 0, MEM_RELEASE);
			return SYS_ENOMEM;
		}
		size_t* length_table = (size_t*)((uintptr_t)utf8_table + (2 * sizeof(char*)));

		utf8_table[0] = (char*)((uintptr_t)utf8_table + (2 * sizeof(char*)) + (2 * sizeof(size_t)));
		utf8_table[1] = 0;
		if (WideCharToMultiByte(CP_UTF8, 0, utf16_executable_name, (int)utf16_executable_name_length, (char*)((uintptr_t)utf8_table + (2 * sizeof(char*)) + (2 * sizeof(size_t))), utf8_executable_name_length, 0, 0) != utf8_executable_name_length)
		{
			VirtualFree(utf16_executable_name, 0, MEM_RELEASE);
			VirtualFree(utf8_table, 0, MEM_RELEASE);
			return SYS_EINVAL;
		}
		*(char*)((uintptr_t)utf8_table + (2 * sizeof(char*)) + (2 * sizeof(size_t)) + (size_t)utf8_executable_name_length) = 0;
		length_table[0] = utf16_executable_name_length;
		length_table[1] = 0;
		VirtualFree(utf16_executable_name, 0, MEM_RELEASE);

		DWORD ignored_old_page_protection;
		if (!VirtualProtect(utf8_table, utf8_table_size, PAGE_READONLY, &ignored_old_page_protection))
		{
			VirtualFree(utf8_table, 0, MEM_RELEASE);
			return SYS_EIO;
		}

		*argument_count_address = 1;
		*argument_length_table_address = length_table;
		*argument_table_address = utf8_table;
		return 0;
	}

	int command_length = WideCharToMultiByte(CP_UTF8, 0, native_command, native_command_length, 0, 0, 0, 0);
	if (!command_length)
		return SYS_EINVAL;

	size_t command_size = ((size_t)command_length + 1);
#ifdef _MSC_VER
	__assume(((command_size + (page_size - 1)) & ~(page_size - 1)) >= command_size);
#endif
	command_size = ((command_size + (page_size - 1)) & ~(page_size - 1));
	char* command = (char*)VirtualAlloc(0, command_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!command)
		return SYS_ENOMEM;

	if (WideCharToMultiByte(CP_UTF8, 0, native_command, native_command_length, command, (int)command_length, 0, 0) != command_length)
	{
		VirtualFree(command, 0, MEM_RELEASE);
		return SYS_EINVAL;
	}
	*(char*)((uintptr_t)command + command_length) = 0;

	int argument_count = 0;
	int argument_character_count = 0;
	int in_argument = 1;
	int in_quotes = 0;
	int backslash_count = 0;
	for (int i = 0; i != command_length; ++i)
	{
		if (command[i] == '\\')
		{
			in_argument = 1;
			++backslash_count;
		}
		else if (command[i] == '"')
		{
			in_argument = 1;
			int quoted_double_quote = in_quotes && i + 1 != command_length && command[i + 1] == '"';
			if (backslash_count && !(backslash_count & 1))
			{
				argument_character_count += (backslash_count / 2);
				in_quotes = !in_quotes;
			}
			else if (backslash_count && (backslash_count & 1))
				argument_character_count += (backslash_count / 2) + 1;
			else
				in_quotes = !in_quotes;
			if (quoted_double_quote)
			{
				++argument_character_count;
				++i;
			}
			backslash_count = 0;
		}
		else if (command[i] == ' ' || command[i] == '\t')
		{
			if (in_argument)
			{
				if (backslash_count)
				{
					argument_character_count += backslash_count;
					backslash_count = 0;
				}
				if (in_quotes)
					++argument_character_count;
				else
				{
					in_argument = 0;
					++argument_count;
				}
			}
		}
		else
		{
			in_argument = 1;
			if (backslash_count)
			{
				argument_character_count += backslash_count;
				backslash_count = 0;
			}
			++argument_character_count;
		}
	}
	if (in_argument)
	{
		if (backslash_count)
		{
			argument_character_count += backslash_count;
			backslash_count = 0;
		}
		++argument_count;
	}

	size_t argument_table_size = ((((size_t)argument_count + 1) * sizeof(char*)) + (((size_t)argument_count + 1) * sizeof(size_t)) + (((size_t)argument_character_count + (size_t)argument_count)));
#ifdef _MSC_VER
	__assume(((argument_table_size + (page_size - 1)) & ~(page_size - 1)) >= argument_table_size);
#endif
	argument_table_size = ((argument_table_size + (page_size - 1)) & ~(page_size - 1));
	char** argument_table = (char**)VirtualAlloc(0, argument_table_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!argument_table)
	{
		VirtualFree(command, 0, MEM_RELEASE);
		return SYS_ENOMEM;
	}
	size_t* length_table = (size_t*)((uintptr_t)argument_table + (((size_t)argument_count + 1) * sizeof(char*)));

	char* argument_write = (char*)((uintptr_t)argument_table + (((size_t)argument_count + 1) * sizeof(char*)) + (((size_t)argument_count + 1) * sizeof(size_t)));
	in_argument = 1;
	in_quotes = 0;
	backslash_count = 0;
	int argument_index = 0;
	argument_table[0] = argument_write;
	for (int i = 0; i != command_length; ++i)
	{
		if (command[i] == '\\')
		{
			if (!in_argument)
			{
				in_argument = 1;
				argument_table[argument_index] = argument_write;
			}
			++backslash_count;
		}
		else if (command[i] == '"')
		{
			if (!in_argument)
			{
				in_argument = 1;
				argument_table[argument_index] = argument_write;
			}
			int quoted_double_quote = in_quotes && i + 1 != command_length && command[i + 1] == '"';
			if (backslash_count && !(backslash_count & 1))
			{
				for (char* fill_end = argument_write + (backslash_count / 2); argument_write != fill_end;)
					*argument_write++ = '\\';
				in_quotes = !in_quotes;
			}
			else if (backslash_count && (backslash_count & 1))
			{
				for (char* fill_end = argument_write + (backslash_count / 2); argument_write != fill_end;)
					*argument_write++ = '\\';
				*argument_write++ = '\"';
			}
			else
				in_quotes = !in_quotes;
			if (quoted_double_quote)
			{
				*argument_write++ = '\"';
				++i;
			}
			backslash_count = 0;
		}
		else if (command[i] == ' ' || command[i] == '\t')
		{
			if (in_argument)
			{
				if (backslash_count)
				{
					for (char* fill_end = argument_write + backslash_count; argument_write != fill_end;)
						*argument_write++ = '\\';
					backslash_count = 0;
				}
				if (in_quotes)
					*argument_write++ = command[i];
				else
				{
					in_argument = 0;
					length_table[argument_index] = (size_t)((uintptr_t)argument_write - (uintptr_t)argument_table[argument_index]);
					*argument_write++ = 0;
					++argument_index;
				}
			}
		}
		else
		{
			if (!in_argument)
			{
				in_argument = 1;
				argument_table[argument_index] = argument_write;
			}
			if (backslash_count)
			{
				for (char* fill_end = argument_write + backslash_count; argument_write != fill_end;)
					*argument_write++ = '\\';
				backslash_count = 0;
			}
			*argument_write++ = command[i];
		}
	}
	if (in_argument)
	{
		if (backslash_count)
		{
			for (char* fill_end = argument_write + backslash_count; argument_write != fill_end;)
				*argument_write++ = '\\';
			backslash_count = 0;
		}
		length_table[argument_index] = (size_t)((uintptr_t)argument_write - (uintptr_t)argument_table[argument_index]);
		*argument_write++ = 0;
		++argument_index;
	}
	length_table[argument_count] = 0;
	argument_table[argument_count] = 0;

	VirtualFree(command, 0, MEM_RELEASE);
	DWORD ignored_old_page_protection;
	if (!VirtualProtect(argument_table, argument_table_size, PAGE_READONLY, &ignored_old_page_protection))
	{
		VirtualFree(argument_table, 0, MEM_RELEASE);
		return SYS_EIO;
	}

	*argument_count_address = (size_t)argument_count;
	*argument_length_table_address = length_table;
	*argument_table_address = argument_table;
	*argument_table_size_address = argument_table_size;
	return 0;
}

int elu_get_process_arguments(size_t* argument_count_address, size_t** argument_length_table_address, char*** argument_table_address, size_t* argument_table_size_address)
{
	const WCHAR* native_command_line = (const WCHAR*)GetCommandLineW();
	if (!native_command_line)
		return SYS_EIO;

	return elu_native_command_line_to_arguments(native_command_line, argument_count_address, argument_length_table_address, argument_table_address, argument_table_size_address);
}

void elu_exit_process(int error)
{
	static const UINT win32_exit_success = 0;
	static const UINT win32_exit_failure = 1;

	ExitProcess(!error ? win32_exit_success : win32_exit_failure);

#ifdef _MSC_VER
	__assume(0);
#endif // _MSC_VER
}

#ifdef _MSC_VER
#pragma warning( pop )
#endif // _MSC_VER

#ifdef __cplusplus
}
#endif