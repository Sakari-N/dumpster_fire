/*
	File access API authored by archiver Sakari N.

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

#ifdef _MSC_VER
#pragma warning( push )

// Buffer read/write overrun. The Microsoft C/C++ compiler is so wrong about these that it is not even funny
#pragma warning( disable : 6385)
#pragma warning( disable : 6386)

// The Microsoft C/C++ compiler frivolous warning mitigation
// Interlocked access nonsense
#pragma warning( disable : 28112)
// Arithmetic overflow
#pragma warning( disable : 26451)

// Is malloc.h needed for _alloca? since it is not really normal function
// Large _alloca
#pragma warning( disable : 6255)

// Large per function stack usage
#pragma warning( disable : 6262)

// GetTickCount
#pragma warning( disable : 28159)

#ifdef ELU_CRT_BASE_SUPPORTED
// I can not write or call __chkstk in C so...
extern void* _elu_chkstk(size_t size);
#define ELU_PRE_ALLOCA_ROUTINE _elu_chkstk
#else
#define ELU_PRE_ALLOCA_ROUTINE
#define ELU_ALLOCA _alloca
#endif

#ifndef ELU_OBJECT_TABLE_LENGTH
#define ELU_OBJECT_TABLE_LENGTH 0x400
#endif // ELU_OBJECT_TABLE_LENGTH

#define WIN32_LEAN_AND_MEAN
#include "elu_file_api.h"

#define ELU_IGNORE_SYSTEM_FILES
//#define ELU_IGNORE_SYSTEM_VOLUME_INFORMATION_DIRECTORY

typedef struct elu_object_t
{
	OVERLAPPED overlapped;
	int type;
	HANDLE handle;
	DWORD error;
	DWORD bytes_transfered;
	void* io_buffer;
	uint32_t volatile * io_progress_marker;
	int io_completed;
	uint8_t padding[32];
} elu_object_t;

typedef struct elu_object_table_t
{
	CRITICAL_SECTION global_lock; // Process wide lock
	size_t size; // size of this table in bytes (The entire allocation)
	uint32_t length; // This may be longer than ELU_IO_TABLE_LENGTH
	uint32_t count; // The count of ongoing IO operations on this table
	uint32_t ready_io_count;
	uint8_t padding[4];
	elu_object_t table[0];
} elu_object_table_t;

// Only one list exist on the process. This is that list
// The pointer to the first table is located by this pointer
// This pointer is located at text segment with the code, so no need for data segment
extern elu_object_table_t volatile * volatile elu_global_object_table;

#else // _MSC_VER

#define ELU_PRE_ALLOCA_ROUTINE
#define ELU_ALLOCA alloca

#endif

// HANDLE elu_debug_get_native_handle_from_elu_handle(elu_handle_t handle) { return elu_global_object_table->table[(int)handle].handle; }

static int elu_get_image_virtual_page_protection(void* address, DWORD* virtual_page_protection_address)
{
	const size_t optional_header_offset = (sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	const IMAGE_DOS_HEADER* dos_header;
	if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (const WCHAR*)address, (HMODULE*)&dos_header))
	{
		return EIO;
	}

	if ((dos_header->e_magic != IMAGE_DOS_SIGNATURE) || (*(const DWORD*)((uintptr_t)dos_header + (uintptr_t)dos_header->e_lfanew) != IMAGE_NT_SIGNATURE))
	{
		return EBADMSG;
	}

	size_t size_of_optional_header = (size_t)((const IMAGE_FILE_HEADER*)((uintptr_t)dos_header + (uintptr_t)dos_header->e_lfanew + sizeof(DWORD)))->SizeOfOptionalHeader;
	if (size_of_optional_header < sizeof(DWORD))
	{
		return EBADMSG;
	}

	WORD optional_header_magic = *(const WORD*)((uintptr_t)dos_header + (uintptr_t)dos_header->e_lfanew + optional_header_offset);
	if (optional_header_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		const IMAGE_OPTIONAL_HEADER32* optional_header = (const IMAGE_OPTIONAL_HEADER32*)((uintptr_t)dos_header + (uintptr_t)dos_header->e_lfanew + optional_header_offset);
		size_t number_of_sections = (size_t)((const IMAGE_FILE_HEADER*)((uintptr_t)dos_header + (uintptr_t)dos_header->e_lfanew + sizeof(DWORD)))->NumberOfSections;
		const IMAGE_SECTION_HEADER* section_header_table = (const IMAGE_SECTION_HEADER*)((uintptr_t)optional_header + size_of_optional_header);
		for (size_t i = 0; i != number_of_sections; ++i)
		{
			uintptr_t virtual_address = (uintptr_t)dos_header + (uintptr_t)section_header_table[i].VirtualAddress;
			size_t virtual_size = (size_t)section_header_table[i].Misc.VirtualSize;
			if (virtual_address <= (uintptr_t)address && (virtual_address + virtual_size) > (uintptr_t)address)
			{
				// just do 3 bit look up table using the three access flag bits IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ and IMAGE_SCN_MEM_WRITE
				static const DWORD access_constant_translation_table[8] = {
					PAGE_NOACCESS,
					PAGE_EXECUTE,
					PAGE_READONLY,
					PAGE_EXECUTE_READ,
					PAGE_READWRITE,
					PAGE_EXECUTE_READWRITE,
					PAGE_READWRITE,
					PAGE_EXECUTE_READWRITE };
				DWORD section_virtual_page_protection = access_constant_translation_table[(section_header_table[i].Characteristics >> 29) & 0x7];
				*virtual_page_protection_address = section_virtual_page_protection;
				return 0;
			}
		}
		return ENOENT;
	}
	else if (optional_header_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		const IMAGE_OPTIONAL_HEADER64* optional_header = (const IMAGE_OPTIONAL_HEADER64*)((uintptr_t)dos_header + (uintptr_t)dos_header->e_lfanew + optional_header_offset);
		size_t number_of_sections = (size_t)((const IMAGE_FILE_HEADER*)((uintptr_t)dos_header + (uintptr_t)dos_header->e_lfanew + sizeof(DWORD)))->NumberOfSections;
		const IMAGE_SECTION_HEADER* section_header_table = (const IMAGE_SECTION_HEADER*)((uintptr_t)optional_header + size_of_optional_header);
		for (size_t i = 0; i != number_of_sections; ++i)
		{
			uintptr_t virtual_address = (uintptr_t)dos_header + (uintptr_t)section_header_table[i].VirtualAddress;
			size_t virtual_size = (size_t)section_header_table[i].Misc.VirtualSize;
			if (virtual_address <= (uintptr_t)address && (virtual_address + virtual_size) > (uintptr_t)address)
			{
				// just do 3 bit look up table using the three access flag bits IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ and IMAGE_SCN_MEM_WRITE
				static const DWORD access_constant_translation_table[8] = {
					PAGE_NOACCESS,
					PAGE_EXECUTE,
					PAGE_READONLY,
					PAGE_EXECUTE_READ,
					PAGE_READWRITE,
					PAGE_EXECUTE_READWRITE,
					PAGE_READWRITE,
					PAGE_EXECUTE_READWRITE };
				DWORD section_virtual_page_protection = access_constant_translation_table[(section_header_table[i].Characteristics >> 29) & 0x7];
				*virtual_page_protection_address = section_virtual_page_protection;
				return 0;
			}
		}
		return ENOENT;
	}
	else
	{
		return EBADMSG;
	}
	
	return EIO;
}

static int elu_create_global_object_table(elu_object_table_t volatile ** global_object_address)
{
	const size_t table_header_size = (size_t)&((const elu_object_table_t*)0)->table;

	SYSTEM_INFO system_info;
	GetSystemInfo(&system_info);
	size_t page_size = (size_t)system_info.dwPageSize;

	size_t object_table_length = (size_t)ELU_OBJECT_TABLE_LENGTH + ((((table_header_size + ((size_t)ELU_OBJECT_TABLE_LENGTH * sizeof(elu_object_t))) + (page_size - 1)) & ~(page_size - 1)) / sizeof(elu_object_t));

#ifdef _MSC_VER
	__assume(object_table_length <= 0xFFFFFFFF);
#endif // _MSC_VER

	size_t size = ((table_header_size + (object_table_length * sizeof(elu_object_t))) + (page_size - 1)) & ~(page_size - 1);
	elu_object_table_t volatile * object_table = (elu_object_table_t volatile *)VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!object_table)
		return ENOMEM;

	InitializeCriticalSection((CRITICAL_SECTION*)&object_table->global_lock);

	object_table->size = size;
	object_table->length = (uint32_t)object_table_length;
	object_table->count = 0;
	object_table->ready_io_count = 0;

	MEMORY_BASIC_INFORMATION memory_range_information;
	if (!VirtualQuery((void*)&elu_global_object_table, &memory_range_information, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		DeleteCriticalSection((CRITICAL_SECTION*)&object_table->global_lock);
		VirtualFree((void*)object_table, 0, MEM_RELEASE);
		return EIO;
	}

	DWORD image_memory_range_virtual_page_protection;
	if (elu_get_image_virtual_page_protection(memory_range_information.BaseAddress, &image_memory_range_virtual_page_protection))
	{
		image_memory_range_virtual_page_protection = PAGE_EXECUTE_READ;// Default to execute and read if something fails.
	}

	DWORD previous_page_protection;
	if (!VirtualProtect(memory_range_information.BaseAddress, memory_range_information.RegionSize, PAGE_EXECUTE_READWRITE, &previous_page_protection))
	{
		DeleteCriticalSection((CRITICAL_SECTION*)&object_table->global_lock);
		VirtualFree((void*)object_table, 0, MEM_RELEASE);
		return EIO;
	}

	elu_object_table_t volatile* previous_global_object_table = 
		(elu_object_table_t volatile*)InterlockedExchangePointer((void * volatile*)&elu_global_object_table, (void*)object_table);

	VirtualProtect(memory_range_information.BaseAddress, memory_range_information.RegionSize, image_memory_range_virtual_page_protection, &previous_page_protection);
	
	if (previous_global_object_table)
	{
		DeleteCriticalSection((CRITICAL_SECTION*)&object_table->global_lock);
		VirtualFree((void*)object_table, 0, MEM_RELEASE);
		*global_object_address = previous_global_object_table;
		return EEXIST;
	}

	*global_object_address = object_table;
	return 0;
}

static int elu_create_object(int object_type, HANDLE native_handle, int* object_index_address)
{
	if (!native_handle)
		return EINVAL;

	elu_object_table_t volatile* global_object_table = elu_global_object_table;
	if (!global_object_table)
	{
		int create_global_object_table_error = elu_create_global_object_table(&global_object_table);
		if (create_global_object_table_error && create_global_object_table_error != EEXIST)
			return create_global_object_table_error;
	}

	size_t table_object_length = (size_t)global_object_table->length;
	size_t object_count = (size_t)global_object_table->count;

	if (object_count == table_object_length)
		return ENFILE;

	size_t object_index = (size_t)~0;
	for (size_t i = 0; i != table_object_length; ++i)
		if (!global_object_table->table[i].handle)
		{
			object_index = i;
			break;
		}

	EnterCriticalSection((CRITICAL_SECTION*)&global_object_table->global_lock);
	object_count = (size_t)global_object_table->count;

	if (object_index == (size_t)~0 || global_object_table->table[object_index].handle)
	{
		if (object_count == table_object_length)
			return ENFILE;

		object_index = (size_t)~0;
		for (size_t i = 0; i != table_object_length; ++i)
			if (!global_object_table->table[i].handle)
			{
				object_index = i;
				break;
			}
		if (object_index == (size_t)~0)
		{
			LeaveCriticalSection((CRITICAL_SECTION*)&global_object_table->global_lock);
			return EIO;// What is this there is supposed to be space when count < length. This should not happen
		}
	}

	global_object_table->table[object_index].type = object_type;
	global_object_table->table[object_index].handle = native_handle;
	global_object_table->table[object_index].error = 0;
	global_object_table->table[object_index].bytes_transfered = 0;
	global_object_table->table[object_index].io_progress_marker = 0;
	global_object_table->table[object_index].io_completed = 0;

	global_object_table->count = (uint32_t)(object_count + 1);
	LeaveCriticalSection((CRITICAL_SECTION*)&global_object_table->global_lock);
	*object_index_address = (int)object_index;
	return 0;
}

static int elu_delete_object(int object_index)
{
	elu_object_table_t volatile* global_object_table = elu_global_object_table;
	if (!global_object_table)
		return ENOENT;

	// IMPORTANT NOTE: DO NOT EVER DELETE OBJECTS WITH IO IN PROGRESS!!!

	HANDLE object_handle = global_object_table->table[object_index].handle;
	if (object_handle != INVALID_HANDLE_VALUE)
	{
		if (!CloseHandle(object_handle))
		{
			switch (GetLastError())
			{
				case ERROR_ACCESS_DENIED:
					return EACCES;
				case ERROR_INVALID_HANDLE:
					return ENOENT;
				default:
					return EIO;
			}
		}
	}

	EnterCriticalSection((CRITICAL_SECTION*)&global_object_table->global_lock);

	global_object_table->table[object_index].type = ELU_OBJECT_TYPE_UNDEFINED;
	global_object_table->table[object_index].handle = 0;
	global_object_table->table[object_index].error = 0;
	global_object_table->table[object_index].bytes_transfered = 0;
	global_object_table->table[object_index].io_progress_marker = 0;
	global_object_table->table[object_index].io_completed = 0;

	global_object_table->count -= 1;
	LeaveCriticalSection((CRITICAL_SECTION*)&global_object_table->global_lock);
	return 0;
}

#ifdef _DEBUG
#define ELU_FILE_API_ASSERT(x) do { if (!(x)) DebugBreak(); } while(0)
#else
#define ELU_FILE_API_ASSERT(x) __assume(x)
#endif

static size_t elu_internal_utf8_root_directory_length(size_t path_langth, const char* path)
{
	if (path_langth > 4 && path[0] == '\\' && path[1] == '\\' && path[2] == '?' && path[3] == '\\')
	{
		if (path_langth > 6 && path[4] != '\\' && path[4] != '/' && path[5] == ':' && (path[6] == '\\' || path[6] == '/'))
			return 7;
		else if ((path[4] == 'U' || path[4] == 'u') && (path[5] == 'N' || path[5] == 'n') && (path[6] == 'C' || path[6] == 'c') && (path[7] == '\\' || path[7] == '/'))
		{
			size_t server_legth = 0;
			while (8 + server_legth < path_langth && path[8 + server_legth] != '\\' && path[8 + server_legth] != '/')
				++server_legth;
			if (!server_legth)
				return 0;
			size_t share_legth = 0;
			while (9 + server_legth + share_legth < path_langth && path[9 + server_legth + share_legth] != '\\' && path[9 + server_legth + share_legth] != '/')
				++share_legth;
			if (!share_legth || path[9 + server_legth + share_legth] != '\\' && path[9 + server_legth + share_legth] != '/')
				return 0;
			return 10 + server_legth + share_legth;
		}
		else
			return 0;
	}
	else
	{
		if (path_langth > 2 && path[0] != '\\' && path[0] != '/' && path[1] == ':' && (path[2] == '\\' || path[2] == '/'))
			return 3;
		else if (path_langth > 2 && (path[0] == '\\' || path[0] == '/') && (path[1] == '\\' || path[1] == '/'))
		{
			size_t server_legth = 0;
			while (2 + server_legth < path_langth && path[2 + server_legth] != '\\' && path[2 + server_legth] != '/')
				++server_legth;
			if (!server_legth)
				return 0;
			size_t share_legth = 0;
			while (3 + server_legth + share_legth < path_langth && path[3 + server_legth + share_legth] != '\\' && path[3 + server_legth + share_legth] != '/')
				++share_legth;
			if (!share_legth || path[3 + server_legth + share_legth] != '\\' && path[3 + server_legth + share_legth] != '/')
				return 0;
			return 4 + server_legth + share_legth;
		}
		else
			return 0;
	}
}

static size_t elu_internal_win32_utf16_root_directory_length(size_t path_langth, const WCHAR* path)
{
	if (path_langth > 4 && path[0] == L'\\' && path[1] == L'\\' && path[2] == L'?' && path[3] == L'\\')
	{
		if (path_langth > 6 && path[4] != L'\\' && path[4] != L'/' && path[5] == L':' && path[6] == L'\\')
			return 7;
		else if ((path[4] == L'U' || path[4] == L'u') && (path[5] == L'N' || path[5] == L'n') && (path[6] == L'C' || path[6] == L'c') && (path[7] == L'\\' || path[7] == L'/'))
		{
			size_t server_legth = 0;
			while (8 + server_legth < path_langth && path[8 + server_legth] != L'\\' && path[8 + server_legth] != L'/')
				++server_legth;
			if (!server_legth)
				return 0;
			size_t share_legth = 0;
			while (9 + server_legth + share_legth < path_langth && path[9 + server_legth + share_legth] != L'\\' && path[9 + server_legth + share_legth] != L'/')
				++share_legth;
			if (!share_legth || path[9 + server_legth + share_legth] != L'\\' && path[9 + server_legth + share_legth] != L'/')
				return 0;
			return 10 + server_legth + share_legth;
		}
		else
			return 0;
	}
	else
	{
		if (path_langth > 2 && path[0] != L'\\' && path[0] != L'/' && path[1] == L':' && path[2] == L'\\')
			return 3;
		else if (path_langth > 2 && (path[0] == L'\\' || path[0] == L'/') && (path[1] == L'\\' || path[1] == L'/'))
		{
			size_t server_legth = 0;
			while (2 + server_legth < path_langth && path[2 + server_legth] != L'\\' && path[2 + server_legth] != L'/')
				++server_legth;
			if (!server_legth)
				return 0;
			size_t share_legth = 0;
			while (3 + server_legth + share_legth < path_langth && path[3 + server_legth + share_legth] != L'\\' && path[3 + server_legth + share_legth] != L'/')
				++share_legth;
			if (!share_legth || path[3 + server_legth + share_legth] != L'\\' && path[3 + server_legth + share_legth] != L'/')
				return 0;
			return 4 + server_legth + share_legth;
		}
		else
			return 0;
	}
}

static size_t elu_internal_win32_utf16_string_length(const WCHAR* string)
{
	const WCHAR* read = string;
	while (*read)
		++read;
	return (size_t)((uintptr_t)read - (uintptr_t)string) / sizeof(WCHAR);
}

static void elu_internal_win32_copy_utf16_string(size_t length, WCHAR* destination, const WCHAR* source)
{
	const WCHAR* source_end = source + length;
	while (source != source_end)
		*destination++ = *source++;
}

static size_t elu_internal_utf8_string_length(const char* string)
{
	const char* read = string;
	while (*read)
		++read;
	return (size_t)((uintptr_t)read - (uintptr_t)string);
}

static void elu_internal_copy_utf8_string(size_t length, char* destination, const char* source)
{
	const char* source_end = source + length;
	while (source != source_end)
		*destination++ = *source++;
}

static void elu_internal_copy_utf8_string_to_extended_path(size_t length, char* destination, const char* source)
{
	const char* source_end = source + length;
	while (source != source_end)
	{
		char character = *source++;
		if (character == '/')
			character = '\\';
		*destination++ = character;
	}
}

static void elu_internal_win32_copy_utf16_string_to_extended_path(size_t length, WCHAR* destination, const WCHAR* source)
{
	const WCHAR* source_end = source + length;
	while (source != source_end)
	{
		WCHAR character = *source++;
		if (character == L'/')
			character = L'\\';
		*destination++ = character;
	}
}

static size_t elu_internal_get_utf8_directory_part_length_from_path(size_t path_length, const char* path)
{
	if (path_length)
	{
		size_t index = path_length - 1;
		for (size_t root_length = elu_internal_utf8_root_directory_length(path_length, path); index != root_length; --index)
			if (path[index] == '\\' || path[index] == '/')
				return index;
	}
	return 0;
}

static size_t elu_internal_win32_get_utf16_directory_part_length_from_path(size_t path_length, const WCHAR* path)
{
	if (path_length)
	{
		size_t index = path_length - 1;
		for (size_t root_length = elu_internal_win32_utf16_root_directory_length(path_length, path); index != root_length; --index)
			if (path[index] == L'\\' || path[index] == L'/')
				return index;
	}
	return 0;
}

static int elu_internal_win32_encode_file_path(size_t path_size, const char* path, size_t* required_buffer_size_address, size_t buffer_size, WCHAR* buffer)
{
	const size_t int_max_value = (size_t)(((unsigned int)~0) >> 1);

	if (!path_size || path_size > int_max_value)
		return EINVAL;

	size_t native_path_length = (size_t)MultiByteToWideChar(CP_UTF8, 0, path, (int)path_size, 0, 0);
	if (!native_path_length)
		return EINVAL;

	if (native_path_length > 0x7FFF)
		return ENAMETOOLONG;

	WCHAR* native_path = (WCHAR*)_alloca((native_path_length + 1) * sizeof(WCHAR));
	if ((size_t)MultiByteToWideChar(CP_UTF8, 0, path, (int)path_size, native_path, (int)native_path_length) != native_path_length)
		return EIO;
	native_path[native_path_length] = 0;

	size_t root_directory_native_path_length = elu_internal_win32_utf16_root_directory_length(native_path_length, native_path);
	if (root_directory_native_path_length)
	{
		if ((native_path_length <= (MAX_PATH - 1)) || (native_path_length > 3 && native_path[0] == L'\\' && native_path[1] == L'\\' && native_path[2] == L'?' && native_path[3] == L'\\'))
		{
			size_t original_native_path_size = native_path_length * sizeof(WCHAR);
			*required_buffer_size_address = original_native_path_size;
			if (buffer_size >= original_native_path_size)
			{
				elu_internal_win32_copy_utf16_string(native_path_length, buffer, native_path);
				return 0;
			}
			else
				return ENOBUFS;
		}
		else if (native_path_length > 2 && native_path[0] != L'\\' && native_path[0] != L'/' && native_path[1] == L':' && (native_path[2] == L'\\' || native_path[2] == L'/'))
		{
			size_t local_native_path_size = (4 + native_path_length) * sizeof(WCHAR);
			*required_buffer_size_address = local_native_path_size;
			if (buffer_size >= local_native_path_size)
			{
				elu_internal_win32_copy_utf16_string(4, buffer, L"\\\\?\\");
				elu_internal_win32_copy_utf16_string_to_extended_path(native_path_length, buffer + 4, native_path);
				return 0;
			}
			else
				return ENOBUFS;
		}
		else if (native_path_length > 2 && (native_path[0] == L'\\' || native_path[0] == L'/') && (native_path[1] == L'\\' || native_path[1] == L'/') && (native_path[2] != L'\\' && native_path[2] != L'/'))
		{
			size_t network_native_path_size = (8 + (native_path_length - 2)) * sizeof(WCHAR);
			*required_buffer_size_address = network_native_path_size;
			if (buffer_size >= network_native_path_size)
			{
				elu_internal_win32_copy_utf16_string(8, buffer, L"\\\\?\\UNC\\");
				elu_internal_win32_copy_utf16_string_to_extended_path(native_path_length - 2, buffer + 8, native_path + 2);
				return 0;
			}
			else
				return ENOBUFS;
		}
		else
			return EINVAL;
	}

	root_directory_native_path_length = elu_internal_win32_utf16_root_directory_length(native_path_length, native_path);
	WCHAR* absolute_native_path;
	if (root_directory_native_path_length)
	{
		absolute_native_path = native_path;
	}
	else
	{
		native_path_length = (size_t)GetFullPathNameW(native_path, 0, 0, 0) - 1;
		if (native_path_length == (size_t)~0 || !native_path_length)
			return EIO;

		if (native_path_length > 0x7FFF)
			return ENAMETOOLONG;

		absolute_native_path = (WCHAR*)_alloca((native_path_length + 1) * sizeof(WCHAR));
		if ((size_t)GetFullPathNameW(native_path, (DWORD)(native_path_length + 1), absolute_native_path, 0) != native_path_length)
			return EIO;

		root_directory_native_path_length = elu_internal_win32_utf16_root_directory_length(native_path_length, absolute_native_path);
		if (!root_directory_native_path_length)
			return EIO;
	}

	if ((native_path_length <= (MAX_PATH - 1)) || (native_path_length > 3 && absolute_native_path[0] == L'\\' && absolute_native_path[1] == L'\\' && absolute_native_path[2] == L'?' && absolute_native_path[3] == L'\\'))
	{
		size_t original_native_path_size = native_path_length * sizeof(WCHAR);
		*required_buffer_size_address = original_native_path_size;
		if (buffer_size >= original_native_path_size)
		{
			elu_internal_win32_copy_utf16_string(native_path_length, buffer, absolute_native_path);
			return 0;
		}
		else
			return ENOBUFS;
	}
	else if (native_path_length > 2 && absolute_native_path[0] != L'\\' && absolute_native_path[0] != L'/' && absolute_native_path[1] == L':' && (absolute_native_path[2] == L'\\' || absolute_native_path[2] == L'/'))
	{
		size_t local_native_path_size = (4 + native_path_length) * sizeof(WCHAR);
		*required_buffer_size_address = local_native_path_size;
		if (buffer_size >= local_native_path_size)
		{
			elu_internal_win32_copy_utf16_string(4, buffer, L"\\\\?\\");
			elu_internal_win32_copy_utf16_string_to_extended_path(native_path_length, buffer + 4, absolute_native_path);
			return 0;
		}
		else
			return ENOBUFS;
	}
	else if (native_path_length > 2 && (absolute_native_path[0] == L'\\' || absolute_native_path[0] == L'/') && (absolute_native_path[1] == L'\\' || absolute_native_path[1] == L'/') && absolute_native_path[2] != L'\\' && absolute_native_path[2] != L'/')
	{
		size_t network_native_path_size = (8 + (native_path_length - 2)) * sizeof(WCHAR);
		*required_buffer_size_address = network_native_path_size;
		if (buffer_size >= network_native_path_size)
		{
			elu_internal_win32_copy_utf16_string(8, buffer, L"\\\\?\\UNC\\");
			elu_internal_win32_copy_utf16_string_to_extended_path(native_path_length - 2, buffer + 8, absolute_native_path + 2);
			return 0;
		}
		else
			return ENOBUFS;
	}
	else
		return EINVAL;
}

static int elu_internal_win32_decode_file_path(size_t path_size, const WCHAR* path, size_t* required_buffer_size_address, size_t buffer_size, char* buffer)
{
	const size_t int_max_value = (size_t)(((unsigned int)~0) >> 1);

	size_t native_name_length = path_size / sizeof(WCHAR);
	if ((path_size % sizeof(WCHAR)) || !native_name_length || native_name_length > int_max_value)
		return EINVAL;

	if (native_name_length > 0x7FFF)
		return ENAMETOOLONG;

	size_t utf8_path_length = (size_t)WideCharToMultiByte(CP_UTF8, 0, path, (int)native_name_length, 0, 0, 0, 0);
	if (!utf8_path_length)
		return EINVAL;

	char* utf8_path = (char*)_alloca((utf8_path_length + 1));
	if ((size_t)WideCharToMultiByte(CP_UTF8, 0, path, (int)native_name_length, utf8_path, (int)utf8_path_length, 0, 0) != utf8_path_length)
		return EIO;

	if (utf8_path_length > 3 && utf8_path[0] == '\\' && utf8_path[1] == '\\' && utf8_path[2] == '?' && utf8_path[3] == '\\')
	{
		if (utf8_path_length > 5 && utf8_path[4] != '\\' && utf8_path[5] == ':' && utf8_path[6] == '\\')
		{
			size_t local_path_size = (utf8_path_length - 4);
			*required_buffer_size_address = local_path_size;
			if (buffer_size >= local_path_size)
			{
				elu_internal_copy_utf8_string(utf8_path_length - 4, buffer, utf8_path + 4);
				return 0;
			}
			else
				return ENOBUFS;
		}
		else if (utf8_path_length > 8 && utf8_path[4] == 'U' && utf8_path[5] == 'N' && utf8_path[6] == 'C' && utf8_path[7] == '\\' && utf8_path[8] != '\\')
		{
			size_t network_path_size = (utf8_path_length - 8) + 2;
			*required_buffer_size_address = network_path_size;
			if (buffer_size >= network_path_size)
			{
				buffer[0] = '\\';
				buffer[1] = '\\';
				elu_internal_copy_utf8_string(utf8_path_length - 8, buffer + 2, utf8_path + 8);
				return 0;
			}
			else
				return ENOBUFS;
		}
		else
			return EINVAL;
	}
	else
	{
		size_t original_path_size = utf8_path_length;
		*required_buffer_size_address = original_path_size;
		if (buffer_size >= original_path_size)
		{
			elu_internal_copy_utf8_string(utf8_path_length, buffer, utf8_path);
			return 0;
		}
		else
			return ENOBUFS;
	}
}

#define ELU_INTERNAL_MAKE_TMP_FILE_NAME_TRY_LIMIT 0x800
static void elu_internal_win32_make_tmp_name(WCHAR* buffer, int try_count)
{
	ELU_FILE_API_ASSERT(try_count < ELU_INTERNAL_MAKE_TMP_FILE_NAME_TRY_LIMIT);

	uint32_t thread_id = (uint32_t)GetCurrentThreadId();
	uint32_t timer = (uint32_t)GetTickCount() / 1000;

	// only 43 low bits are used
	uint64_t tmp_number = ((uint64_t)((thread_id & 0xFFFF) ^ ((thread_id >> 16) & 0xFFFF)) << 27) | ((uint64_t)(timer & 0xFFFF) << 11) | (uint64_t)(try_count & 0x7FF);

	static const WCHAR digit_table[] = {
		L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8',
		L'9', L'A', L'B', L'C', L'D', L'E', L'F', L'G', L'H',
		L'I', L'J', L'K', L'L', L'M', L'N', L'O', L'P', L'Q',
		L'R', L'S', L'T', L'U', L'V', L'W', L'X', L'Y', L'Z',
		L'!', L'#', L'$', L'%', L'&', L'_' };
	const uint64_t digit_count = sizeof(digit_table) / sizeof(*digit_table);

	for (int i = 0; i != 8; ++i)
	{
		buffer[i] = digit_table[tmp_number % digit_count];
		tmp_number /= digit_count;
	}

	buffer[8] = 0;
}

static void elu_internal_win32_make_tmp_8dot3_file_name(WCHAR* buffer, int try_count)
{
	elu_internal_win32_make_tmp_name(buffer, try_count);

	buffer[8] = L'.';
	buffer[9] = L'T';
	buffer[10] = L'M';
	buffer[11] = L'P';
	buffer[12] = 0;
}

static int elu_internal_win32_undo_create_directory(size_t name_length, WCHAR* name, size_t undo_index)
{
	int error = 0;
	for (size_t iterator = name_length; iterator != (undo_index - 1); --iterator)
	{
		WCHAR name_character = name[iterator];
		if (iterator == name_length || name_character == L'\\' || name_character == L'/')
		{
			name[iterator] = 0;
			BOOL remove_successful = RemoveDirectoryW(name);
			name[iterator] = name_character;
			if (!error && !remove_successful)
			{
				DWORD native_error = GetLastError();
				switch (native_error)
				{
					case ERROR_FILE_NOT_FOUND:
						error = ENOENT;
						break;
					case ERROR_PATH_NOT_FOUND:
						error = ENOENT;
						break;
					case ERROR_ACCESS_DENIED:
						error = EACCES;
						break;
					case ERROR_INVALID_NAME:
						error = ENOENT;
						break;
					default:
						error = EIO;
						break;
				}
			}
		}
	}
	return error;
}

static int elu_internal_win32_create_directory(size_t name_length, WCHAR* name, size_t* undo_index)
{
	for (size_t root_length = elu_internal_win32_utf16_root_directory_length(name_length, name),
		high_iterator = name_length; high_iterator != (root_length - 1); --high_iterator)
	{
		WCHAR name_character = name[high_iterator];
		if (high_iterator == name_length || name_character == L'\\' || name_character == L'/')
		{
			name[high_iterator] = 0;
			DWORD native_error = CreateDirectoryW(name, 0) ? 0 : GetLastError();
			name[high_iterator] = name_character;

			if (!native_error)
			{
				for (size_t last_create_index = high_iterator, low_iterator = high_iterator + 1; low_iterator != (name_length + 1); ++low_iterator)
				{
					name_character = name[low_iterator];
					if (low_iterator == name_length || name_character == L'\\' || name_character == L'/')
					{
						name[low_iterator] = 0;
						native_error = CreateDirectoryW(name, 0) ? 0 : GetLastError();
						name[low_iterator] = name_character;

						if (native_error && native_error != ERROR_ALREADY_EXISTS)
						{
							elu_internal_win32_undo_create_directory(last_create_index, name, high_iterator);
							switch (native_error)
							{
								case ERROR_ACCESS_DENIED:
									return EACCES;
								case ERROR_INVALID_NAME:
									return EINVAL;
								case ERROR_ALREADY_EXISTS:
									return EEXIST;
								default:
									return EIO;
							}
						}
						else
							last_create_index = low_iterator;
					}
				}
				*undo_index = high_iterator;
				return 0;
			}
			else if (native_error != ERROR_PATH_NOT_FOUND)
			{
				switch (native_error)
				{
					case ERROR_ACCESS_DENIED:
						return EACCES;
					case ERROR_INVALID_NAME:
						return EINVAL;
					case ERROR_ALREADY_EXISTS:
						return EEXIST;
					default:
						return EIO;
				}
			}
		}
	}
	return ENOENT;
}

int elu_open_file(size_t name_length, const char* name, int permissions_and_flags, elu_handle_t* handle_address)
{
	if (name_length < 1)
		return EINVAL;

	size_t native_name_size;
	int error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	WCHAR* native_name = (WCHAR*)_alloca(native_name_size + sizeof(WCHAR));
	error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, native_name_size, native_name);
	if (error)
		return error;
	*(WCHAR*)((uintptr_t)native_name + native_name_size) = 0;

	DWORD desired_access =
		((permissions_and_flags & ELU_READ_PERMISION) ? GENERIC_READ : 0) |
		((permissions_and_flags & ELU_WRITE_PERMISION) ? GENERIC_WRITE : 0);
	if (!desired_access)
		return EINVAL;

	DWORD creation_disposition =
		(permissions_and_flags & ELU_CREATE) ? ((permissions_and_flags & ELU_TRUNCATE) ? CREATE_ALWAYS : CREATE_NEW) : OPEN_EXISTING;

	DWORD flags_and_attributes = FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL | (((permissions_and_flags & ELU_SEQUENTIAL_ACCESS) && (permissions_and_flags & ELU_READ_PERMISION) && !(permissions_and_flags & ELU_WRITE_PERMISION)) ? FILE_FLAG_SEQUENTIAL_SCAN : 0);

	HANDLE handle = CreateFileW(native_name, desired_access, ((desired_access == GENERIC_READ) ? FILE_SHARE_READ : 0), 0, creation_disposition, flags_and_attributes, 0);

	if (handle == INVALID_HANDLE_VALUE)
	{
		DWORD native_error = GetLastError();

		if ((native_error == ERROR_PATH_NOT_FOUND) && ((permissions_and_flags & (ELU_CREATE_PATH | ELU_CREATE | ELU_WRITE_PERMISION)) == (ELU_CREATE_PATH | ELU_CREATE | ELU_WRITE_PERMISION)))
		{
			size_t create_directory_undo_index;
			size_t directory_part_length = elu_internal_win32_get_utf16_directory_part_length_from_path(native_name_size / sizeof(WCHAR), native_name);
			error = directory_part_length ? elu_internal_win32_create_directory(directory_part_length, native_name, &create_directory_undo_index) : ENOENT;
			if (error)
				return error;

			handle = CreateFileW(native_name, desired_access, ((desired_access == GENERIC_READ) ? FILE_SHARE_READ : 0),
				0, creation_disposition, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, 0);
			if (handle == INVALID_HANDLE_VALUE)
			{
				native_error = GetLastError();
				elu_internal_win32_undo_create_directory(directory_part_length, native_name, create_directory_undo_index);
			}
		}

		if (handle == INVALID_HANDLE_VALUE)
			switch (native_error)
			{
				case ERROR_FILE_NOT_FOUND:
					return ENOENT;
				case ERROR_PATH_NOT_FOUND:
					return ENOENT;
				case ERROR_ACCESS_DENIED:
					return EACCES;
				case ERROR_FILE_EXISTS:
					return EEXIST;
				case ERROR_INVALID_NAME:
					return ENOENT;
				default:
					return EIO;
			}
	}

	ELU_FILE_API_ASSERT(handle != INVALID_HANDLE_VALUE);

	int object_index;
	error = elu_create_object(ELU_OBJECT_TYPE_FILE, handle, &object_index);
	if (error)
	{
		CloseHandle(handle);
		return error;
	}

	*handle_address = (elu_handle_t)object_index;
	return 0;
}

int elu_close_file(elu_handle_t handle)
{
	return elu_delete_object((int)handle);

	/*
	if (!CloseHandle((HANDLE)handle))
		switch (GetLastError())
		{
			case ERROR_ACCESS_DENIED:
				return EACCES;
			case ERROR_INVALID_HANDLE:
				return ENOENT;
			default:
				return EIO;
		}

	return 0;
	*/
}

int elu_get_path_preferred_io_block_size(size_t name_length, const char* name, size_t* io_size_address)
{
	const size_t int_max_value = (size_t)(((unsigned int)~0) >> 1);

	if (!name_length || name_length > int_max_value)
		return EINVAL;

	size_t native_name_size;
	int error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	WCHAR* native_name = (WCHAR*)_alloca(native_name_size + sizeof(WCHAR));
	error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, native_name_size, native_name);
	if (error)
		return error;

	size_t root_directory_length = elu_internal_win32_utf16_root_directory_length(native_name_size / sizeof(WCHAR), native_name);
	if (!root_directory_length)
		return EIO;

	*(WCHAR*)((uintptr_t)native_name + root_directory_length) = 0;
	DWORD sectors_per_cluster;
	DWORD bytes_per_sector;
	DWORD number_of_free_clusters;
	DWORD total_number_of_clusters;
	DWORD native_error = GetDiskFreeSpaceW(native_name, &sectors_per_cluster, &bytes_per_sector, &number_of_free_clusters, &total_number_of_clusters) ? 0 : GetLastError();
	if (native_error)
	{
		switch (native_error)
		{
			case ERROR_FILE_NOT_FOUND:
				return ENOENT;
			case ERROR_PATH_NOT_FOUND:
				return ENOENT;
			case ERROR_ACCESS_DENIED:
				return EACCES;
			case ERROR_INVALID_NAME:
				return ENOENT;
			default:
				return EIO;
		}
	}

	size_t preferred_io_size = (size_t)sectors_per_cluster * (size_t)bytes_per_sector;
	if (!preferred_io_size)
		preferred_io_size = 1;
	*io_size_address = preferred_io_size;
	return 0;
}

int elu_get_file_preferred_io_block_size(elu_handle_t handle, size_t* io_size_address)
{
	HANDLE native_handle = elu_global_object_table->table[(int)handle].handle;

	WCHAR file_path_buffer[0x7FFF + 1];
	size_t file_path_length = (size_t)GetFinalPathNameByHandleW(native_handle, file_path_buffer, (DWORD)(sizeof(file_path_buffer) / sizeof(WCHAR)), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
	DWORD native_error = file_path_length ? ((file_path_length <= 0x7FFF) ? 0 : ERROR_INVALID_NAME) : GetLastError();
	if (!native_error)
	{
		int extended_path;
		size_t root_directory_length;
		if (file_path_length > 4 && file_path_buffer[0] == L'\\' && file_path_buffer[1] == L'\\' && file_path_buffer[2] == L'?' && file_path_buffer[3] == L'\\')
		{
			extended_path = 1;
			if (file_path_length > 6 && file_path_buffer[4] != L'\\' && file_path_buffer[4] != L'/' && file_path_buffer[5] == L':' && (file_path_buffer[6] == L'\\' || file_path_buffer[6] == L'/'))
				root_directory_length = 7;
			else if ((file_path_buffer[4] == L'U' || file_path_buffer[4] == L'u') && (file_path_buffer[5] == L'N' || file_path_buffer[5] == L'n') && (file_path_buffer[6] == L'C' || file_path_buffer[6] == L'c') && (file_path_buffer[7] == L'\\' || file_path_buffer[7] == L'/'))
			{
				size_t server_legth = 0;
				while (8 + server_legth < file_path_length && file_path_buffer[8 + server_legth] != L'\\' && file_path_buffer[8 + server_legth] != L'/')
					++server_legth;
				if (!server_legth)
					root_directory_length = 0;
				else
				{
					size_t share_legth = 0;
					while (9 + server_legth + share_legth < file_path_length && file_path_buffer[9 + server_legth + share_legth] != L'\\' && file_path_buffer[9 + server_legth + share_legth] != L'/')
						++share_legth;
					if (!share_legth || file_path_buffer[9 + server_legth + share_legth] != L'\\' && file_path_buffer[9 + server_legth + share_legth] != L'/')
						root_directory_length = 0;
					else
						root_directory_length = 10 + server_legth + share_legth;
				}
			}
			else
				root_directory_length = 0;
		}
		else
		{
			extended_path = 0;
			if (file_path_length > 2 && file_path_buffer[0] != L'\\' && file_path_buffer[0] != L'/' && file_path_buffer[1] == L':' && (file_path_buffer[2] == L'\\' || file_path_buffer[2] == L'/'))
				root_directory_length = 3;
			else if (file_path_length > 2 && (file_path_buffer[0] == L'\\' || file_path_buffer[0] == L'/') && (file_path_buffer[1] == L'\\' || file_path_buffer[1] == L'/'))
			{
				size_t server_legth = 0;
				while (2 + server_legth < file_path_length && file_path_buffer[2 + server_legth] != L'\\' && file_path_buffer[2 + server_legth] != L'/')
					++server_legth;
				if (!server_legth)
					root_directory_length = 0;
				else
				{
					size_t share_legth = 0;
					while (3 + server_legth + share_legth < file_path_length && file_path_buffer[3 + server_legth + share_legth] != L'\\' && file_path_buffer[3 + server_legth + share_legth] != L'/')
						++share_legth;
					if (!share_legth || file_path_buffer[3 + server_legth + share_legth] != L'\\' && file_path_buffer[3 + server_legth + share_legth] != L'/')
						root_directory_length = 0;
					else
						root_directory_length = 4 + server_legth + share_legth;
				}
			}
			else
				root_directory_length = 0;
		}
		if (root_directory_length)
		{
			if (extended_path)
			{
				if (root_directory_length > 8 && (file_path_buffer[4] == L'U' || file_path_buffer[4] == L'u') && (file_path_buffer[5] == L'N' || file_path_buffer[5] == L'n') && (file_path_buffer[6] == L'C' || file_path_buffer[6] == L'c') && file_path_buffer[7] == L'\\')
				{
					for (WCHAR* move = file_path_buffer + 8, *move_end = file_path_buffer + root_directory_length; move != move_end; ++move)
						*(move - 6) = *move;
					root_directory_length -= 6;
				}
				else
				{
					for (WCHAR* move = file_path_buffer + 4, *move_end = file_path_buffer + root_directory_length; move != move_end; ++move)
						*(move - 4) = *move;
					root_directory_length -= 4;
				}
			}

			file_path_buffer[root_directory_length] = 0;
			DWORD sectors_per_cluster;
			DWORD bytes_per_sector;
			DWORD number_of_free_clusters;
			DWORD total_number_of_clusters;
			native_error = GetDiskFreeSpaceW(file_path_buffer, &sectors_per_cluster, &bytes_per_sector, &number_of_free_clusters, &total_number_of_clusters) ? 0 : GetLastError();
			if (!native_error)
			{
				size_t preferred_io_size = (size_t)sectors_per_cluster * (size_t)bytes_per_sector;
				if (!preferred_io_size)
					preferred_io_size = 1;
				*io_size_address = preferred_io_size;
				return 0;
			}
		}
		else
			native_error = ERROR_INVALID_NAME;
	}

	FILE_STORAGE_INFO file_storage_info;
	native_error = GetFileInformationByHandleEx(native_handle, FileStorageInfo, (LPVOID)&file_storage_info, (DWORD)sizeof(FILE_STORAGE_INFO)) ? 0 : GetLastError(); /* Requires Windows 8 or later */
	if (native_error)
	{
		switch (native_error)
		{
			case ERROR_INVALID_HANDLE:
				return EIO;
			case ERROR_FILE_NOT_FOUND:
				return ENOENT;
			case ERROR_PATH_NOT_FOUND:
				return ENOENT;
			case ERROR_ACCESS_DENIED:
				return EACCES;
			case ERROR_INVALID_NAME:
				return ENOENT;
			default:
				return EIO;
		}
	}
	size_t preferred_io_size = file_storage_info.PhysicalBytesPerSectorForPerformance;
	if (file_storage_info.LogicalBytesPerSector)
		preferred_io_size = ((preferred_io_size + ((size_t)file_storage_info.LogicalBytesPerSector - 1)) / (size_t)file_storage_info.LogicalBytesPerSector) * (size_t)file_storage_info.LogicalBytesPerSector;
	if (!preferred_io_size)
		preferred_io_size = 1;
	*io_size_address = preferred_io_size;
	return 0;
}

static int elu_internal_get_file_size(HANDLE handle, uint64_t* file_size_address)
{
	if (!GetFileSizeEx(handle, (LARGE_INTEGER*)file_size_address))
	{
		switch (GetLastError())
		{
		case ERROR_ACCESS_DENIED:
			return EACCES;
		case ERROR_INVALID_HANDLE:
			return ENOENT;
		default:
			return EIO;
		}
	}

	return 0;
}

int elu_get_file_size(elu_handle_t handle, uint64_t* file_size_address)
{
	HANDLE native_handle = elu_global_object_table->table[(int)handle].handle;
	return elu_internal_get_file_size(native_handle, file_size_address);
}

int elu_truncate_file(elu_handle_t handle, uint64_t file_size)
{
	HANDLE native_handle = elu_global_object_table->table[(int)handle].handle;

	if (file_size & 0x8000000000000000)
		return EINVAL;

	if (!SetFileInformationByHandle(native_handle, FileEndOfFileInfo, &file_size, sizeof(uint64_t)))
	{
		switch (GetLastError())
		{
			case ERROR_ACCESS_DENIED:
				return EACCES;
			case ERROR_INVALID_HANDLE:
				return ENOENT;
			default:
				return EIO;
		}
	}

	return 0;
}

int elu_flush_file_buffers(elu_handle_t handle)
{
	HANDLE native_handle = elu_global_object_table->table[(int)handle].handle;

	if (!FlushFileBuffers(native_handle))
	{
		switch (GetLastError())
		{
			case ERROR_ACCESS_DENIED:
				return EACCES;
			case ERROR_INVALID_HANDLE:
				return ENOENT;
			default:
				return EIO;
		}
	}

	return 0;
}

static void WINAPI elu_io_completion_routine(DWORD error, DWORD bytes_transfered, volatile elu_object_t* overlapped_data)
{
	overlapped_data->error = error;
	overlapped_data->bytes_transfered = bytes_transfered;
	overlapped_data->io_completed = 1;

	LONG volatile * io_progress_marker = overlapped_data->io_progress_marker;
	if (io_progress_marker)
	{
		InterlockedIncrement(io_progress_marker);
	}
}

int elu_read_file(elu_handle_t handle, uint64_t file_offset, size_t io_size, void* buffer)
{
	size_t object_index = (size_t)handle;
	HANDLE native_handle = elu_global_object_table->table[object_index].handle;
	elu_object_t volatile* object = elu_global_object_table->table + object_index;

	object->overlapped.Internal = 0;
	object->overlapped.InternalHigh = 0;
	object->overlapped.Offset = (DWORD)(file_offset & 0xFFFFFFFF);
	object->overlapped.OffsetHigh = (DWORD)(file_offset >> 32);
	object->overlapped.hEvent = 0;
	object->error = ERROR_UNIDENTIFIED_ERROR;
	object->io_buffer = buffer;
	object->bytes_transfered = 0;
	object->io_completed = 0;
	object->io_progress_marker = &elu_global_object_table->ready_io_count;
	DWORD io_transfer_size = ((io_size < (size_t)0x80000000) ? (DWORD)io_size : (DWORD)0x80000000);
	BOOL io_request_successful = ReadFileEx(native_handle, (void*)buffer, io_transfer_size, (OVERLAPPED*)object, (LPOVERLAPPED_COMPLETION_ROUTINE)elu_io_completion_routine);
	if (!io_request_successful)
	{
		object->io_progress_marker = 0;
		DWORD native_error = GetLastError();
		if (!native_error)
			native_error = ERROR_UNIDENTIFIED_ERROR;
		if (native_error == ERROR_HANDLE_EOF)
			return ENODATA;
		else
			return EIO;
	}

	return 0;

	/*
	// Old blocking version of the function
	
	size_t object_index = (size_t)handle;
	HANDLE native_handle = elu_global_object_table->table[object_index].handle;
	elu_object_t volatile * object = elu_global_object_table->table + object_index;
	object->io_progress_marker = 0;// Not used in this operation

	DWORD maximum_io_size = 0x80000000;
	for (size_t file_read = 0; file_read != io_size;)
	{
		ULONGLONG overlapped_offset = (ULONGLONG)file_offset + (ULONGLONG)file_read;
		object->overlapped.Internal = 0;
		object->overlapped.InternalHigh = 0;
		object->overlapped.Offset = (DWORD)(overlapped_offset & 0xFFFFFFFF);
		object->overlapped.OffsetHigh = (DWORD)(overlapped_offset >> 32);
		object->overlapped.hEvent = 0;
		object->error = ERROR_UNIDENTIFIED_ERROR;
		object->bytes_transfered = 0;
		object->io_completed = 0;

		DWORD io_transfer_size = (((io_size - file_read) < (size_t)maximum_io_size) ? (DWORD)(io_size - file_read) : (DWORD)maximum_io_size);
		DWORD error = ReadFileEx(native_handle, (void*)((uintptr_t)buffer + file_read), io_transfer_size, (OVERLAPPED*)object, (LPOVERLAPPED_COMPLETION_ROUTINE)elu_io_completion_routine) ? 0 : ERROR_UNIDENTIFIED_ERROR;
		if (!error)
		{
			while (!object->io_completed)
				SleepEx(INFINITE, TRUE);

			object->io_completed = 0;
			error = object->error;
			if (error)
			{
				if (error != ERROR_HANDLE_EOF)
					return ENODATA;
				else
					return EIO;
			}
			file_read += (size_t)object->bytes_transfered;
		}
		else
		{
			if (io_transfer_size > 0x100000 && maximum_io_size > 0x100000)
				maximum_io_size = 0x100000;
			else
				return EIO;
		}
	}

	return 0;
	*/
}

int elu_write_file(elu_handle_t handle, uint64_t file_offset, size_t io_size, const void* buffer)
{
	size_t object_index = (size_t)handle;
	HANDLE native_handle = elu_global_object_table->table[object_index].handle;
	elu_object_t volatile* object = elu_global_object_table->table + object_index;

	object->overlapped.Internal = 0;
	object->overlapped.InternalHigh = 0;
	object->overlapped.Offset = (DWORD)(file_offset & 0xFFFFFFFF);
	object->overlapped.OffsetHigh = (DWORD)(file_offset >> 32);
	object->overlapped.hEvent = 0;
	object->error = ERROR_UNIDENTIFIED_ERROR;
	object->io_buffer = (void*)buffer;
	object->bytes_transfered = 0;
	object->io_completed = 0;
	object->io_progress_marker = &elu_global_object_table->ready_io_count;
	DWORD io_transfer_size = ((io_size < (size_t)0x80000000) ? (DWORD)io_size : (DWORD)0x80000000);
	BOOL io_request_successful = WriteFileEx(native_handle, (void*)buffer, io_transfer_size, (OVERLAPPED*)object, (LPOVERLAPPED_COMPLETION_ROUTINE)elu_io_completion_routine);
	if (!io_request_successful)
	{
		object->io_progress_marker = 0;
		DWORD native_error = GetLastError();
		if (!native_error)
			native_error = ERROR_UNIDENTIFIED_ERROR;
		if (native_error == ERROR_HANDLE_EOF)
			return ENODATA;
		else
			return EIO;
	}

	return 0;

	/*
	// Old blocking version of the function

	size_t object_index = (size_t)handle;
	HANDLE native_handle = elu_global_object_table->table[object_index].handle;
	elu_object_t volatile* object = elu_global_object_table->table + object_index;
	object->io_progress_marker = 0;// Not used in this operation

	DWORD maximum_io_size = 0x80000000;
	for (size_t file_written = 0; file_written != io_size;)
	{
		ULONGLONG overlapped_offset = (ULONGLONG)file_offset + (ULONGLONG)file_written;
		object->overlapped.Internal = 0;
		object->overlapped.InternalHigh = 0;
		object->overlapped.Offset = (DWORD)(overlapped_offset & 0xFFFFFFFF);
		object->overlapped.OffsetHigh = (DWORD)(overlapped_offset >> 32);
		object->overlapped.hEvent = 0;
		object->error = ERROR_UNIDENTIFIED_ERROR;
		object->bytes_transfered = 0;
		object->io_completed = 0;

		DWORD io_transfer_size = (((io_size - file_written) < (size_t)maximum_io_size) ? (DWORD)(io_size - file_written) : (DWORD)maximum_io_size);
		DWORD error = WriteFileEx(native_handle, (void*)((uintptr_t)buffer + file_written), io_transfer_size, (OVERLAPPED*)object, (LPOVERLAPPED_COMPLETION_ROUTINE)elu_io_completion_routine) ? 0 : ERROR_UNIDENTIFIED_ERROR;
		if (!error)
		{
			while (!object->io_completed)
				SleepEx(INFINITE, TRUE);

			object->io_completed = 0;
			error = object->error;
			if (error)
			{
				if (error != ERROR_HANDLE_EOF)
					return ENODATA;
				else
					return EIO;
			}
			file_written += (size_t)object->bytes_transfered;
		}
		else
		{
			if (io_transfer_size > 0x100000 && maximum_io_size > 0x100000)
				maximum_io_size = 0x100000;
			else
				return EIO;
		}
	}

	return 0;
	*/
}

int elu_wait(uint32_t timeout_milliseconds, size_t handle_count, elu_handle_t* handle_table, size_t* io_completion_count_address, elu_io_result_t* io_completion_result_table)
{
	// Currently only ELU_IO_TYPE_DATA_TRANSFER for files is supported
	elu_object_table_t volatile * object_table = elu_global_object_table;
	size_t object_table_length = object_table->length;

	uint32_t start_time_ms = (timeout_milliseconds && timeout_milliseconds != INFINITE) ? 0 : GetTickCount();
	for (int first_wait = 1, read_new_io_data = 1; read_new_io_data;)
	{
		size_t ready_io_count = object_table->ready_io_count;
		if (handle_count && ready_io_count)
		{
			size_t ready_io_read_count = 0;
			for (size_t i = 0; ready_io_read_count != ready_io_count && i != handle_count; ++i)
			{
				size_t object_index = (size_t)handle_table[i];
				if (object_table->table[object_index].io_completed)
				{
					InterlockedDecrement((LONG volatile*)&object_table->ready_io_count);
					object_table->table[object_index].io_progress_marker = 0;
					object_table->table[object_index].io_completed = 0;

					io_completion_result_table[ready_io_read_count].handle = (elu_handle_t)object_index;
					io_completion_result_table[ready_io_read_count].object_type = object_table->table[object_index].type;
					io_completion_result_table[ready_io_read_count].io_type = ELU_IO_TYPE_DATA_TRANSFER;
					io_completion_result_table[ready_io_read_count].result_error = !object_table->table[object_index].error ? 0 : ((object_table->table[object_index].error != ERROR_HANDLE_EOF) ? EIO : ENODATA);

					io_completion_result_table[ready_io_read_count].data_transfer.size = (size_t)object_table->table[object_index].bytes_transfered;
					io_completion_result_table[ready_io_read_count].data_transfer.buffer = object_table->table[object_index].io_buffer;

					++ready_io_read_count;
				}
			}
			if (ready_io_read_count)
			{
				*io_completion_count_address = ready_io_read_count;
				return 0;
			}
		}

		read_new_io_data = 0;
		uint32_t timeout_milliseconds_remaining;
		if (first_wait || timeout_milliseconds == INFINITE)
			timeout_milliseconds_remaining = timeout_milliseconds;
		else
		{
			timeout_milliseconds_remaining = GetTickCount() - start_time_ms;
			timeout_milliseconds_remaining = (timeout_milliseconds_remaining < timeout_milliseconds) ? (timeout_milliseconds - timeout_milliseconds_remaining) : 0;
		}
		if (first_wait || timeout_milliseconds_remaining)
		{
#ifdef ELU_GUI_SUPPORT
			DWORD native_block_result = MsgWaitForMultipleObjectsEx(0, 0, timeout_milliseconds_remaining, 0, MWMO_ALERTABLE);
#else
			DWORD native_block_result = SleepEx(timeout_milliseconds_remaining, TRUE);
#endif
			if (native_block_result == WAIT_TIMEOUT)
			{
				return ETIME;
			}
			else if (native_block_result != WAIT_IO_COMPLETION)
			{
				return EIO;
			}
			first_wait = 0;
			read_new_io_data = 1;
		}
	}

	return ETIME;
}

int elu_cancel_io(elu_handle_t handle)
{
	size_t object_index = (size_t)handle;
	HANDLE native_handle = elu_global_object_table->table[object_index].handle;
	elu_object_t volatile* object = elu_global_object_table->table + object_index;

	CancelIo(native_handle);

	return 0;
}

int elu_load_file(size_t name_length, const char* name, size_t buffer_size, void* buffer, size_t* file_size_address)
{
	if (name_length < 1)
		return EINVAL;

	size_t native_name_size;
	int error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	WCHAR* native_name = (WCHAR*)_alloca(native_name_size + sizeof(WCHAR));
	error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, native_name_size, native_name);
	if (error)
		return error;
	*(WCHAR*)((uintptr_t)native_name + native_name_size) = 0;

	HANDLE handle = CreateFileW(native_name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, buffer_size ? FILE_FLAG_SEQUENTIAL_SCAN : 0, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		DWORD create_native_error = GetLastError();
		switch (create_native_error)
		{
			case ERROR_FILE_NOT_FOUND:
				return ENOENT;
			case ERROR_PATH_NOT_FOUND:
				return ENOENT;
			case ERROR_ACCESS_DENIED:
				return EACCES;
			case ERROR_FILE_EXISTS:
				return EEXIST;
			case ERROR_INVALID_NAME:
				return ENOENT;
			default:
				return EIO;
		}
	}

#ifdef _WIN64
	ELU_FILE_API_ASSERT(sizeof(size_t) == sizeof(uint64_t));

	size_t file_size;
	error = elu_internal_get_file_size(handle, (uint64_t*)&file_size);// FIX THIS!
	if (error)
	{
		CloseHandle(handle);
		return error;
	}
#else
	ELU_FILE_API_ASSERT(sizeof(size_t) == sizeof(uint32_t));

	uint64_t native_file_size;
	error = elu_get_file_size((HANDLE)handle, &native_file_size);
	if (error)
	{
		CloseHandle(handle);
		return error;
	}
	if (native_file_size > (uint64_t)0xFFFFFFFF)
	{
		CloseHandle(handle);
		return E2BIG;
	}
	size_t file_size = (size_t)native_file_size;
#endif

	*file_size_address = file_size;
	if (file_size > buffer_size)
	{
		CloseHandle(handle);
		return ENOBUFS;
	}

	DWORD maximum_io_size = 0x80000000;
	DWORD transfer_size;
	for (size_t file_read = 0; file_read != file_size;)
	{
		DWORD io_transfer_size = ((file_size - file_read) < (size_t)maximum_io_size) ? (DWORD)(file_size - file_read) : maximum_io_size;
		if (ReadFile(handle, (void*)((uintptr_t)buffer + file_read), io_transfer_size, &transfer_size, 0) && transfer_size)
			file_read += (size_t)transfer_size;
		else
		{
			if (io_transfer_size > 0x100000 && maximum_io_size > 0x100000)
				maximum_io_size = 0x100000;
			else
			{
				CloseHandle(handle);
				return EIO;
			}
		}
	}

	CloseHandle(handle);
	return 0;
}

int elu_allocate_and_load_file(size_t name_length, const char* name, elu_allocator_context_t* allocator_context, size_t* file_size_address, void** file_data_address)
{
	if (name_length < 1)
		return EINVAL;

	size_t native_name_size;
	int error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	WCHAR* native_name = (WCHAR*)_alloca(native_name_size + sizeof(WCHAR));
	error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, native_name_size, native_name);
	if (error)
		return error;
	*(WCHAR*)((uintptr_t)native_name + native_name_size) = 0;

	HANDLE handle = CreateFileW(native_name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		DWORD create_native_error = GetLastError();
		switch (create_native_error)
		{
			case ERROR_FILE_NOT_FOUND:
				return ENOENT;
			case ERROR_PATH_NOT_FOUND:
				return ENOENT;
			case ERROR_ACCESS_DENIED:
				return EACCES;
			case ERROR_FILE_EXISTS:
				return EEXIST;
			case ERROR_INVALID_NAME:
				return ENOENT;
			default:
				return EIO;
		}
	}

#ifdef _WIN64
	ELU_FILE_API_ASSERT(sizeof(size_t) == sizeof(uint64_t));

	size_t file_size;
	error = elu_internal_get_file_size(handle, (uint64_t*)&file_size);// FIX THIS!
	if (error)
	{
		CloseHandle(handle);
		return error;
	}
#else
	ELU_FILE_API_ASSERT(sizeof(size_t) == sizeof(uint32_t));

	uint64_t native_file_size;
	error = elu_get_file_size((HANDLE)handle, &native_file_size);
	if (error)
	{
		CloseHandle(handle);
		return error;
	}
	if (native_file_size > (uint64_t)0xFFFFFFFF)
	{
		CloseHandle(handle);
		return E2BIG;
	}
	size_t file_size = (size_t)native_file_size;
#endif

	*file_size_address = file_size;

	void* file_data = allocator_context->allocator_procedure(allocator_context->context, file_size);
	if (!file_data)
	{
		CloseHandle(handle);
		return ENOBUFS;
	}

	DWORD maximum_io_size = 0x80000000;
	DWORD transfer_size;
	for (size_t file_read = 0; file_read != file_size;)
	{
		DWORD io_transfer_size = ((file_size - file_read) < (size_t)maximum_io_size) ? (DWORD)(file_size - file_read) : maximum_io_size;
		if (ReadFile(handle, (void*)((uintptr_t)file_data + file_read), io_transfer_size, &transfer_size, 0) && transfer_size)
			file_read += (size_t)transfer_size;
		else
		{
			if (io_transfer_size > 0x100000 && maximum_io_size > 0x100000)
				maximum_io_size = 0x100000;
			else
			{
				allocator_context->deallocator_procedure(allocator_context->context, file_size, file_data);
				CloseHandle(handle);
				return EIO;
			}
		}
	}

	CloseHandle(handle);
	*file_data_address = file_data;
	return 0;
}

int elu_store_file(size_t name_length, const char* name, size_t size, const void* data)
{
	if (name_length < 1)
		return EINVAL;

	size_t native_name_size;
	int error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	const size_t maximum_length_from_path_extension = 6;

	// TMP name is 8 dot 3 type name
	const size_t tmp_file_name_part_length = 12;

	FILE_RENAME_INFO* native_name = (FILE_RENAME_INFO*)_alloca((size_t)(&((const FILE_RENAME_INFO*)0)->FileName) + (native_name_size + sizeof(WCHAR)) + ((native_name_size + tmp_file_name_part_length + maximum_length_from_path_extension + 1) * sizeof(WCHAR)));
	error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, native_name_size, native_name->FileName);
	if (error)
		return error;
	WCHAR* native_tmp_file_name = (WCHAR*)((uintptr_t)native_name + (size_t)(&((const FILE_RENAME_INFO*)0)->FileName) + (native_name_size + sizeof(WCHAR)));

	int native_name_length = (int)native_name_size / sizeof(WCHAR);
	
	// native_name->ReplaceIfExists = TRUE;
	// Write to flags instead to zero all unknown flags values and set ReplaceIfExists to TRUE
	native_name->Flags = 0x00000001;
	native_name->RootDirectory = 0;
	native_name->FileNameLength = (DWORD)native_name_length;
	native_name->FileName[native_name_length] = 0;

	int native_file_name_length = 0;
	while (native_file_name_length != native_name_length && native_name->FileName[(native_name_length - 1) - native_file_name_length] != '\\' && native_name->FileName[(native_name_length - 1) - native_file_name_length] != '/')
		++native_file_name_length;

	if (!native_file_name_length)
		return EINVAL;

	int native_directory_path_length = native_name_length - native_file_name_length;
	int native_tmp_directory_path_length;
	if (((native_directory_path_length + tmp_file_name_part_length) <= (MAX_PATH - 1)) || (native_directory_path_length > 3 && native_name->FileName[0] == L'\\' && native_name->FileName[1] == L'\\' && native_name->FileName[2] == L'?' && native_name->FileName[3] == L'\\'))
	{
		elu_internal_win32_copy_utf16_string((size_t)native_directory_path_length, native_tmp_file_name, native_name->FileName);
		native_tmp_directory_path_length = native_directory_path_length;
	}
	else
	{
		if (native_directory_path_length > 2 && (native_name->FileName[0] != L'\\' && native_name->FileName[0] != L'/') && (native_name->FileName[1] == L':') && (native_name->FileName[2] == L'\\' || native_name->FileName[2] == L'/'))
		{
			elu_internal_win32_copy_utf16_string(4, native_tmp_file_name, L"\\\\?\\");
			elu_internal_win32_copy_utf16_string_to_extended_path(native_directory_path_length, native_tmp_file_name + 4, native_name->FileName);
			native_tmp_directory_path_length = native_directory_path_length + 4;
		}
		else if (native_directory_path_length > 2 && (native_name->FileName[0] == L'\\' || native_name->FileName[0] == L'/') && (native_name->FileName[1] == L'\\' || native_name->FileName[1] == L'/') && (native_name->FileName[2] != L'\\' && native_name->FileName[2] != L'/'))
		{
			elu_internal_win32_copy_utf16_string(8, native_tmp_file_name, L"\\\\?\\UNC\\");
			elu_internal_win32_copy_utf16_string_to_extended_path((size_t)(native_directory_path_length - 2), native_tmp_file_name + 8, native_name->FileName + 2);
			native_tmp_directory_path_length = native_directory_path_length + 6;
		}
		else
			return EINVAL;
	}
	// Add the tmp file name part later.

	size_t create_directory_undo_index = (size_t)~0;
	HANDLE handle = INVALID_HANDLE_VALUE;
	for (int try_count = 0; handle == INVALID_HANDLE_VALUE;)
	{
		elu_internal_win32_make_tmp_8dot3_file_name(native_tmp_file_name + native_tmp_directory_path_length, try_count);

		handle = CreateFileW(native_tmp_file_name, GENERIC_WRITE | DELETE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
		if (handle == INVALID_HANDLE_VALUE)
		{
			DWORD create_native_error = GetLastError();
			if (create_native_error == ERROR_FILE_EXISTS)
			{
				if (try_count != ELU_INTERNAL_MAKE_TMP_FILE_NAME_TRY_LIMIT)
					++try_count;
				else
				{
					if (create_directory_undo_index != (size_t)~0)
						elu_internal_win32_undo_create_directory((size_t)(native_tmp_directory_path_length - 1), native_tmp_file_name, create_directory_undo_index);

					return EEXIST;
				}
			}
			else if (create_native_error == ERROR_PATH_NOT_FOUND && native_tmp_directory_path_length && create_directory_undo_index == (size_t)~0)
			{
				int create_directory_error = elu_internal_win32_create_directory((size_t)(native_tmp_directory_path_length - 1), native_tmp_file_name, &create_directory_undo_index);
				if (create_directory_error)
					return create_directory_error;
			}
			else
			{
				if (create_directory_undo_index != (size_t)~0)
					elu_internal_win32_undo_create_directory((size_t)(native_tmp_directory_path_length - 1), native_tmp_file_name, create_directory_undo_index);

				switch (create_native_error)
				{
					case ERROR_FILE_NOT_FOUND:
						return ENOENT;
					case ERROR_PATH_NOT_FOUND:
						return ENOENT;
					case ERROR_ACCESS_DENIED:
						return EACCES;
					case ERROR_INVALID_NAME:
						return ENOENT;
					default:
						return EIO;
				}
			}
		}
	}

#ifdef _WIN64
	if (size & 0x8000000000000000)
	{
		CloseHandle(handle);
		DeleteFileW(native_tmp_file_name);
		if (create_directory_undo_index != (size_t)~0)
			elu_internal_win32_undo_create_directory((size_t)(native_tmp_directory_path_length - 1), native_tmp_file_name, create_directory_undo_index);
		return EINVAL;
	}

	if (!SetFileInformationByHandle(handle, FileEndOfFileInfo, &size, sizeof(uint64_t)))
#else
	uint64_t native_file_size = (uint64_t)size;
	if (!SetFileInformationByHandle(handle, FileEndOfFileInfo, &native_file_size, sizeof(uint64_t)))
#endif
	{
		CloseHandle(handle);
		DeleteFileW(native_tmp_file_name);
		if (create_directory_undo_index != (size_t)~0)
			elu_internal_win32_undo_create_directory((size_t)(native_tmp_directory_path_length - 1), native_tmp_file_name, create_directory_undo_index);
		return EIO;
	}

	DWORD maximum_io_size = 0x80000000;
	DWORD transfer_size;
	for (size_t file_written = 0; file_written != size;)
	{
		DWORD io_transfer_size = ((size - file_written) < (size_t)maximum_io_size) ? (DWORD)(size - file_written) : maximum_io_size;
		if (WriteFile(handle, (const void*)((uintptr_t)data + file_written), io_transfer_size, &transfer_size, 0) && transfer_size)
			file_written += (size_t)transfer_size;
		else
		{
			if (io_transfer_size > 0x100000 && maximum_io_size > 0x100000)
				maximum_io_size = 0x100000;
			else
			{
				CloseHandle(handle);
				DeleteFileW(native_tmp_file_name);
				if (create_directory_undo_index != (size_t)~0)
					elu_internal_win32_undo_create_directory((size_t)(native_tmp_directory_path_length - 1), native_tmp_file_name, create_directory_undo_index);
				return EIO;
			}
		}
	}

	if (!FlushFileBuffers(handle))
	{
		CloseHandle(handle);
		DeleteFileW(native_tmp_file_name);
		if (create_directory_undo_index != (size_t)~0)
			elu_internal_win32_undo_create_directory((size_t)(create_directory_undo_index - 1), native_tmp_file_name, create_directory_undo_index);
		return EIO;
	}

	if (!SetFileInformationByHandle(handle, FileRenameInfo, native_name, (DWORD)((size_t)(&((const FILE_RENAME_INFO*)0)->FileName) + (native_name_size + sizeof(WCHAR)))))
	{
		CloseHandle(handle);
		DeleteFileW(native_tmp_file_name);
		if (create_directory_undo_index != (size_t)~0)
			elu_internal_win32_undo_create_directory((size_t)(create_directory_undo_index - 1), native_tmp_file_name, create_directory_undo_index);
		return EIO;
	}

	CloseHandle(handle);
	return 0;
}

int elu_delete_file(size_t name_length, const char* name)
{
	if (name_length < 1)
		return EINVAL;

	size_t native_name_size;
	int error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	WCHAR* native_name = (WCHAR*)_alloca(native_name_size + sizeof(WCHAR));
	error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, native_name_size, native_name);
	if (error)
		return error;
	*(WCHAR*)((uintptr_t)native_name + native_name_size) = 0;

	if (!DeleteFileW(native_name))
	{
		DWORD native_error = GetLastError();
		switch (native_error)
		{
			case ERROR_FILE_NOT_FOUND:
				return ENOENT;
			case ERROR_PATH_NOT_FOUND:
				return ENOENT;
			case ERROR_ACCESS_DENIED:
				return EACCES;
			case ERROR_INVALID_NAME:
				return ENOENT;
			default:
				return EIO;
		}
	}

	return 0;
}

#ifdef ELU_IGNORE_SYSTEM_VOLUME_INFORMATION_DIRECTORY
static int elu_internal_win32_is_directory_system_volume_information(DWORD directory_attributes, size_t directory_name_length, const WCHAR* directory_name)
{
	// "System Volume Information"
	static const WCHAR system_volume_information_directory_name[] = { L'S', L'Y', L'S', L'T', L'E', L'M', L' ', L'V', L'O', L'L', L'U', L'M', L'E', L' ', L'I', L'N', L'F', L'O', L'R', L'M', L'A', L'T', L'I', L'O', 'N' };
	const size_t system_volume_information_directory_name_length = sizeof(system_volume_information_directory_name) / sizeof(*system_volume_information_directory_name);

	if (directory_name_length && (directory_name[directory_name_length - 1] == L'\\' || directory_name[directory_name_length - 1] == L'/'))
		--directory_name_length;

	if (directory_name_length < (MAX_PATH - 1))
	{
		size_t root_directory_name_length = elu_internal_win32_utf16_root_directory_length(directory_name_length, directory_name);
		if (root_directory_name_length && directory_name_length == (root_directory_name_length + system_volume_information_directory_name_length))
		{
			int directory_name_match = 1;
			for (size_t i = 0; directory_name_match && i != system_volume_information_directory_name_length; ++i)
			{
				WCHAR character = directory_name[root_directory_name_length + i];
				// Convert to uppercase
				character = ((character < 0x61) || (character > 0x7A)) ? character : (character - 0x20);
				directory_name_match = (int)(character == system_volume_information_directory_name[i]);
			}
			if (directory_name_match)
			{
				if ((directory_attributes != INVALID_FILE_ATTRIBUTES) && ((directory_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM)) == (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM)))
					return 1;
			}
		}
	}

	return 0;
}
#endif

static size_t elu_internal_win32_get_allocation_granularity()
{
	SYSTEM_INFO system_info;
	GetSystemInfo(&system_info);
	return (size_t)(system_info.dwAllocationGranularity > system_info.dwPageSize ? system_info.dwAllocationGranularity : system_info.dwPageSize);
}

#define ELU_INTERNAL_WIN32_OBJECT_FLAG_DIRECTORY 0x0001

typedef struct elu_internal_win32_object_t
{
	uint16_t flags;
	uint16_t previous_name_length;
	uint16_t name_length;
	WCHAR name[0];
} elu_internal_win32_object_t;

#define ELU_INTERNAL_WIN32_OBJECT_BLOCK_ALLOCATION_EXPONENT_LIMIT 7
#define ELU_INTERNAL_WIN32_OBJECT_BLOCK_ALLOCATION_GRANULARITY 0x20000

typedef struct elu_internal_win32_object_list_t
{
	size_t size;
	size_t used_size;
	size_t allocation_granularity;
	size_t object_count;
	elu_internal_win32_object_t* first;
	elu_internal_win32_object_t* last;
} elu_internal_win32_object_list_t;

static elu_internal_win32_object_list_t* elu_internal_win32_allocate_object_list()
{
	SYSTEM_INFO system_info;
	GetSystemInfo(&system_info);
	size_t initial_size = (ELU_INTERNAL_WIN32_OBJECT_BLOCK_ALLOCATION_GRANULARITY + ((size_t)system_info.dwAllocationGranularity - 1)) & ~((size_t)system_info.dwAllocationGranularity - 1);

	elu_internal_win32_object_list_t* list = (elu_internal_win32_object_list_t*)VirtualAlloc(0, initial_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!list)
		return 0;

	list->size = initial_size;
	list->used_size = sizeof(elu_internal_win32_object_list_t);
	list->allocation_granularity = (size_t)system_info.dwAllocationGranularity;
	list->object_count = 0;
	list->first = 0;
	list->last = 0;

	return list;
}

static int elu_internal_win32_reallocate_object_list(elu_internal_win32_object_list_t** object_list_address, size_t required_size)
{
	elu_internal_win32_object_list_t* list = *object_list_address;
	size_t size = list->size;
	if (required_size > size)
	{
		size_t new_size = size;
		while (new_size < ELU_INTERNAL_WIN32_OBJECT_BLOCK_ALLOCATION_GRANULARITY && new_size < required_size)
			new_size <<= 1;
		while (new_size < required_size)
			new_size += ELU_INTERNAL_WIN32_OBJECT_BLOCK_ALLOCATION_GRANULARITY;

		elu_internal_win32_object_list_t* new_list = (elu_internal_win32_object_list_t*)VirtualAlloc(0, new_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (new_list)
		{
			new_list->size = new_size;
			new_list->used_size = list->used_size;
			new_list->allocation_granularity = list->allocation_granularity;
			new_list->object_count = list->object_count;
			new_list->first = (elu_internal_win32_object_t*)((uintptr_t)new_list + (uintptr_t)list->first - (uintptr_t)list);
			new_list->last = (elu_internal_win32_object_t*)((uintptr_t)new_list + (uintptr_t)list->last - (uintptr_t)list);
			for (uint8_t* source = (uint8_t*)((uintptr_t)list + sizeof(elu_internal_win32_object_list_t)), *source_end = (uint8_t*)((uintptr_t)list + list->used_size), *destination = (uint8_t*)((uintptr_t)new_list + sizeof(elu_internal_win32_object_list_t)); source != source_end; ++source, ++destination)
				*destination = *source;
			VirtualFree(list, 0, MEM_RELEASE);
			*object_list_address = new_list;
			return 1;
		}
		else
			return 0;
	}
	else
		return 1;
}

static void elu_internal_win32_deallocate_object_list(elu_internal_win32_object_list_t* object_list)
{
	VirtualFree(object_list, 0, MEM_RELEASE);
}

static size_t elu_internal_win32_list_directory_extend_path_in_place(size_t path_length, WCHAR* path_buffer)
{
	if ((path_length >= 2) && (path_buffer[0] != L'\\' && path_buffer[0] != L'/') && (path_buffer[1] == L':'))
	{
		if (4 + path_length > 0x7FFD)
			return 4 + path_length;
		for (WCHAR* i = path_buffer + path_length; i != path_buffer; --i)
		{
			WCHAR move_character = *i;
			if (move_character == L'/')
				move_character = L'\\';
			*(i + 4) = move_character;
		}
		path_buffer[0] = L'\\';
		path_buffer[1] = L'\\';
		path_buffer[2] = L'?';
		path_buffer[3] = L'\\';
		return 4 + path_length;
	}
	else if ((path_length >= 2) && (path_buffer[0] == L'\\' || path_buffer[0] == L'/') && (path_buffer[1] == L'\\' || path_buffer[1] == L'/'))
	{
		if (6 + path_length > 0x7FFD)
			return 6 + path_length;
		for (WCHAR* e = path_buffer + 2, * i = path_buffer + path_length; i != e; --i)
		{
			WCHAR move_character = *i;
			if (move_character == L'/')
				move_character = L'\\';
			*(i + 6) = move_character;
		}
		path_buffer[0] = L'\\';
		path_buffer[1] = L'\\';
		path_buffer[2] = L'?';
		path_buffer[3] = L'\\';
		path_buffer[4] = L'U';
		path_buffer[5] = L'N';
		path_buffer[6] = L'C';
		path_buffer[7] = L'\\';
		return 6 + path_length;
	}
	else
		return (size_t)~0;
}

static int elu_internal_win32_list_directory(size_t base_name_length, WCHAR* name_buffer, elu_internal_win32_object_list_t** object_list_address)
{
	const size_t object_header_size = (size_t)(&((const elu_internal_win32_object_t*)0)->name);

	if (!base_name_length)
		return EINVAL;

	if (base_name_length > 0x7FFD)
		return ENAMETOOLONG;

	elu_internal_win32_object_list_t* list = elu_internal_win32_allocate_object_list();
	if (!list)
		return ENOMEM;

	for (size_t current_directory_name_length = base_name_length, list_offset = (size_t)~0, index = (size_t)~0; index != list->object_count;)
	{
		if (current_directory_name_length && (name_buffer[current_directory_name_length - 1] == L'\\' || name_buffer[current_directory_name_length - 1] == L'/'))
			--current_directory_name_length;
		int current_directory_name_is_extended = (current_directory_name_length > 3) && (name_buffer[0] == L'\\' && name_buffer[1] == L'\\' && name_buffer[2] == L'?' && name_buffer[3] == L'\\');
		if (((current_directory_name_length + 2) > (MAX_PATH - 1)) && !current_directory_name_is_extended)
		{
			current_directory_name_is_extended = 1;
			current_directory_name_length = elu_internal_win32_list_directory_extend_path_in_place(current_directory_name_length, name_buffer);
			int path_extend_error;
			if (current_directory_name_length == (size_t)~0)
				path_extend_error = EINVAL;
			else if (current_directory_name_length > 0x7FFD)
				path_extend_error = ENAMETOOLONG;
			else
				path_extend_error = 0;
			if (path_extend_error)
			{
				elu_internal_win32_deallocate_object_list(list);
				return path_extend_error;
			}
		}
		name_buffer[current_directory_name_length] = L'\\';
		name_buffer[current_directory_name_length + 1] = L'*';
		name_buffer[current_directory_name_length + 2] = 0;
		WIN32_FIND_DATAW find_data;
		HANDLE find_handle = FindFirstFileExW(name_buffer, FindExInfoBasic, &find_data, FindExSearchNameMatch, 0, FIND_FIRST_EX_LARGE_FETCH);
		DWORD native_find_error;
		if (find_handle == INVALID_HANDLE_VALUE)
		{
			native_find_error = GetLastError();
			elu_internal_win32_deallocate_object_list(list);
			switch (native_find_error)
			{
				case ERROR_FILE_NOT_FOUND:
					return ENOENT;
				case ERROR_PATH_NOT_FOUND:
					return ENOENT;
				case ERROR_ACCESS_DENIED:
					return EACCES;
				case ERROR_INVALID_NAME:
					return ENOENT;
				default:
					return EIO;
			}
		}
		native_find_error = 0;

		while (!native_find_error)
		{
			size_t file_name_length = elu_internal_win32_utf16_string_length(find_data.cFileName);
			if (current_directory_name_length + 1 + file_name_length > 0x7FFF)
			{
				FindClose(find_handle);
				elu_internal_win32_deallocate_object_list(list);
				return ENAMETOOLONG;
			}

			int add_find = !(file_name_length == 1 && find_data.cFileName[0] == '.') && !(file_name_length == 2 && find_data.cFileName[0] == '.' && find_data.cFileName[1] == '.');

			if (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
			{
				// Ignore symbolic links.
				add_find = 0;
			}
#ifdef ELU_IGNORE_SYSTEM_FILES
			if (find_data.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
			{
				add_find = 0;
			}
#else
#ifdef ELU_IGNORE_SYSTEM_VOLUME_INFORMATION_DIRECTORY
			if (add_find && (find_data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM)) == (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM))
			{
				int temporary_extended_current_directory_name = (current_directory_name_length + 1 + file_name_length) > (MAX_PATH - 1) && !current_directory_name_is_extended;
				if (temporary_extended_current_directory_name)
				{
					size_t extended_current_directory_name_length = elu_internal_win32_list_directory_extend_path_in_place(current_directory_name_length, name_buffer);
					int path_extend_error;
					if (extended_current_directory_name_length == (size_t)~0)
						path_extend_error = EINVAL;
					else if (extended_current_directory_name_length > 0x7FFD)
						path_extend_error = ENAMETOOLONG;
					else
						path_extend_error = 0;
					if (path_extend_error)
					{
						FindClose(find_handle);
						elu_internal_win32_deallocate_object_list(list);
						return path_extend_error;
					}
				}
				add_find = !elu_internal_win32_is_directory_system_volume_information(find_data.dwFileAttributes, file_name_length, name_buffer);
				if (temporary_extended_current_directory_name)
				{
					if ((name_buffer[4] == L'U' || name_buffer[4] == L'u') && (name_buffer[5] == L'N' || name_buffer[5] == L'n') && (name_buffer[6] == L'C' || name_buffer[6] == L'c') && name_buffer[7] == L'\\')
					{
						name_buffer[0] = L'\\';
						name_buffer[1] = L'\\';
						for (WCHAR* l = name_buffer + current_directory_name_length, * i = name_buffer + 2; i != l; ++i)
							*i = *(i + 6);
					}
					else
					{
						for (WCHAR* l = name_buffer + current_directory_name_length, *i = name_buffer; i != l; ++i)
							*i = *(i + 4);
					}
				}
			}
#endif // ELU_IGNORE_SYSTEM_VOLUME_INFORMATION_DIRECTORY
#endif // ELU_IGNORE_SYSTEM_FILES
			if (add_find)
			{
				size_t required_extansion_expansion_length = 0;
				if (!current_directory_name_is_extended && ((current_directory_name_length + 1 + file_name_length) > (MAX_PATH - 1)))
				{
					if ((name_buffer[0] == '\\' || name_buffer[0] == '/') && (name_buffer[1] == '\\' || name_buffer[1] == '/'))
						required_extansion_expansion_length = 6;
					else
						required_extansion_expansion_length = 4;
				}
				size_t object_size = (object_header_size + ((required_extansion_expansion_length + current_directory_name_length + 1 + file_name_length) * sizeof(WCHAR)));
				size_t required_list_size = list->used_size + object_size;
				if (required_list_size > list->size)
				{
					if (!elu_internal_win32_reallocate_object_list(&list, required_list_size))
					{
						elu_internal_win32_deallocate_object_list(list);
						return ENOMEM;
					}
				}

				elu_internal_win32_object_t* object = (elu_internal_win32_object_t*)((uintptr_t)list + list->used_size);
				list->used_size += object_size;

				object->flags = (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? ELU_INTERNAL_WIN32_OBJECT_FLAG_DIRECTORY : 0;
				object->previous_name_length = list->object_count ? list->last->name_length : 0;
				object->name_length = (uint16_t)(required_extansion_expansion_length + current_directory_name_length + 1 + file_name_length);
				WCHAR* name = object->name;
				if (required_extansion_expansion_length)
				{
					name[0] = L'\\';
					name[1] = L'\\';
					name[2] = L'?';
					name[3] = L'\\';
					if (required_extansion_expansion_length == 4)
					{
						elu_internal_win32_copy_utf16_string_to_extended_path(current_directory_name_length, name + 4, name_buffer);
						*(name + 4 + current_directory_name_length) = L'\\';
						elu_internal_win32_copy_utf16_string(file_name_length, name + 4 + current_directory_name_length + 1, find_data.cFileName);
					}
					else
					{
#ifdef _MSC_VER
						__assume(required_extansion_expansion_length == 6);
#endif // _MSC_VER
						name[4] = L'U';
						name[5] = L'N';
						name[6] = L'C';
						name[7] = L'\\';
						elu_internal_win32_copy_utf16_string_to_extended_path(current_directory_name_length - 2, name + 8, name_buffer + 2);
						*(name + 6 + current_directory_name_length) = L'\\';
						elu_internal_win32_copy_utf16_string(file_name_length, name + 6 + current_directory_name_length + 1, find_data.cFileName);
					}
				}
				else
				{
					elu_internal_win32_copy_utf16_string(current_directory_name_length, name, name_buffer);
					*(name + current_directory_name_length) = L'\\';
					elu_internal_win32_copy_utf16_string(file_name_length, name + current_directory_name_length + 1, find_data.cFileName);
				}

				list->last = object;
				if (!list->object_count)
					list->first = object;
				list->object_count++;
			}

			native_find_error = FindNextFileW(find_handle, &find_data) ? 0 : GetLastError();
		}

		FindClose(find_handle);
		if (native_find_error != ERROR_NO_MORE_FILES)
		{
			elu_internal_win32_deallocate_object_list(list);
			return EIO;
		}

		// Note: (size_t)~0 + 1 = 0
		++index;
		list_offset = (list_offset != (size_t)~0) ? (list_offset + object_header_size + ((size_t)((elu_internal_win32_object_t*)((uintptr_t)list + list_offset))->name_length * sizeof(WCHAR))) : (size_t)((uintptr_t)list->first - (uintptr_t)list);
		while (index != list->object_count && !(((elu_internal_win32_object_t*)((uintptr_t)list + list_offset))->flags & ELU_INTERNAL_WIN32_OBJECT_FLAG_DIRECTORY))
		{
			++index;
			list_offset += (object_header_size + ((size_t)((elu_internal_win32_object_t*)((uintptr_t)list + list_offset))->name_length * sizeof(WCHAR)));
		}
		if (index != list->object_count)
		{
			elu_internal_win32_object_t* current_directory = (elu_internal_win32_object_t*)((uintptr_t)list + list_offset);
			current_directory_name_length = (size_t)current_directory->name_length;
			for (WCHAR* source = current_directory->name, * source_end = current_directory->name + current_directory_name_length, * destination = name_buffer; source != source_end; ++source, ++destination)
				*destination = *source;
		}
	}

	*object_list_address = list;
	return 0;
}

int elu_list_directory(size_t name_length, const char* name, size_t buffer_size, elu_file_entry_t* buffer, size_t* required_buffer_size_address, size_t* directory_count_address, size_t* file_count_address)
{
	const size_t object_header_size = (size_t)(&((const elu_internal_win32_object_t*)0)->name);

	if (name_length < 1)
		return EINVAL;

	size_t native_name_size;
	int error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	WCHAR* native_name_buffer = (WCHAR*)_alloca((0x7FFF + 1) * sizeof(WCHAR));
	error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, native_name_size, native_name_buffer);
	if (error)
		return error;
	*(WCHAR*)((uintptr_t)native_name_buffer + native_name_size) = 0;

	elu_internal_win32_object_list_t* object_list;
	error = elu_internal_win32_list_directory(native_name_size / sizeof(WCHAR), native_name_buffer, &object_list);
	if (error)
		return error;

	size_t directory_count = 0;
	size_t file_count = 0;
	size_t text_size = 0;
	size_t object_utf8_name_size;
	elu_internal_win32_object_t* object = object_list->first;
	for (size_t n = object_list->object_count, i = 0; i != n; object = (elu_internal_win32_object_t*)((uintptr_t)object + object_header_size + ((size_t)object->name_length * sizeof(WCHAR))), ++i)
	{
		error = elu_internal_win32_decode_file_path((size_t)object->name_length * sizeof(WCHAR), object->name, &object_utf8_name_size, 0, 0);
		if (error && error != ENOBUFS)
		{
			elu_internal_win32_deallocate_object_list(object_list);
			return error;
		}
		text_size += object_utf8_name_size + 1;
		if (object->flags & ELU_INTERNAL_WIN32_OBJECT_FLAG_DIRECTORY)
			++directory_count;
		else
			++file_count;
	}

	size_t required_size = ((directory_count + file_count) * sizeof(elu_file_entry_t)) + text_size;
	*required_buffer_size_address = required_size;
	*directory_count_address = directory_count;
	*file_count_address = file_count;
	if (required_size > buffer_size)
	{
		elu_internal_win32_deallocate_object_list(object_list);
		return ENOBUFS;
	}

	size_t write_offset = (directory_count + file_count) * sizeof(elu_file_entry_t);
	object = object_list->first;
	for (size_t i = 0; i != directory_count; object = (elu_internal_win32_object_t*)((uintptr_t)object + object_header_size + ((size_t)object->name_length * sizeof(WCHAR))))
		if (object->flags & ELU_INTERNAL_WIN32_OBJECT_FLAG_DIRECTORY)
		{
			if (write_offset == required_size)
			{
				elu_internal_win32_deallocate_object_list(object_list);
				return EIO;
			}
			buffer[i].name = (char*)((uintptr_t)buffer + write_offset);
			error = elu_internal_win32_decode_file_path((size_t)object->name_length * sizeof(WCHAR), object->name, &object_utf8_name_size, required_size - (write_offset + 1), buffer[i].name);
			if (error)
			{
				elu_internal_win32_deallocate_object_list(object_list);
				return error;
			}
			buffer[i].name_length = object_utf8_name_size;
			*(buffer[i].name + object_utf8_name_size) = 0;
			write_offset += object_utf8_name_size + 1;
			++i;
		}

	object = object_list->first;
	for (size_t i = 0; i != file_count; object = (elu_internal_win32_object_t*)((uintptr_t)object + object_header_size + ((size_t)object->name_length * sizeof(WCHAR))))
		if (!(object->flags & ELU_INTERNAL_WIN32_OBJECT_FLAG_DIRECTORY))
		{
			if (write_offset == required_size)
			{
				elu_internal_win32_deallocate_object_list(object_list);
				return EIO;
			}
			buffer[directory_count + i].name = (char*)((uintptr_t)buffer + write_offset);
			error = elu_internal_win32_decode_file_path((size_t)object->name_length * sizeof(WCHAR), object->name, &object_utf8_name_size, required_size - (write_offset + 1), buffer[directory_count + i].name);
			if (error)
			{
				elu_internal_win32_deallocate_object_list(object_list);
				return error;
			}
			buffer[directory_count + i].name_length = object_utf8_name_size;
			*(buffer[directory_count + i].name + object_utf8_name_size) = 0;
			write_offset += object_utf8_name_size + 1;
			++i;
		}

	elu_internal_win32_deallocate_object_list(object_list);
	return 0;
}

int elu_delete_directory(size_t name_length, const char* name)
{
	const size_t object_header_size = (size_t)(&((const elu_internal_win32_object_t*)0)->name);

	if (name_length < 1)
		return EINVAL;

	size_t native_name_size;
	int error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	const size_t maximum_length_from_path_extension = 6;

	// TMP name is 8 dot 3 type name
	const size_t tmp_file_name_part_length = 12;

	// Note: Pretty large allocation 64 to 192 KiB
	WCHAR* native_name_buffer = (WCHAR*)_alloca(((0x7FFF + 1) * sizeof(WCHAR)) + (native_name_size + sizeof(WCHAR)) + (native_name_size + ((maximum_length_from_path_extension + 1 + tmp_file_name_part_length + 1) * sizeof(WCHAR*))));
	WCHAR* native_name = (WCHAR*)((uintptr_t)native_name_buffer + ((0x7FFF + 1) * sizeof(WCHAR)));
	WCHAR* native_tmp_name = (WCHAR*)((uintptr_t)native_name_buffer + ((0x7FFF + 1) * sizeof(WCHAR)) + (native_name_size + sizeof(WCHAR)));
	error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, native_name_size, native_name);
	if (error)
		return error;
	*(WCHAR*)((uintptr_t)native_name + native_name_size) = 0;

	int native_name_length = (int)(native_name_size / sizeof(WCHAR));
	if (elu_internal_win32_utf16_root_directory_length((size_t)native_name_length, native_name) == (size_t)native_name_length)
		return EINVAL;

	int native_file_name_length = 0;
	while (native_file_name_length != native_name_length && native_name[(native_name_length - 1) - native_file_name_length] != '\\' && native_name[(native_name_length - 1) - native_file_name_length] != '/')
		++native_file_name_length;

	if (!native_file_name_length)
		return EINVAL;

	int native_directory_path_length = native_name_length - native_file_name_length;
	int native_tmp_directory_path_length;
	if (((native_directory_path_length + tmp_file_name_part_length) <= (MAX_PATH - 1)) || (native_directory_path_length > 3 && native_name[0] == L'\\' && native_name[1] == L'\\' && native_name[2] == L'?' && native_name[3] == L'\\'))
	{
		elu_internal_win32_copy_utf16_string((size_t)native_directory_path_length, native_tmp_name, native_name);
		native_tmp_directory_path_length = native_directory_path_length;
	}
	else
	{
		if (native_directory_path_length > 2 && (native_name[0] != L'\\' && native_name[0] != L'/') && (native_name[1] == L':') && (native_name[2] == L'\\' || native_name[2] == L'/'))
		{
			elu_internal_win32_copy_utf16_string(4, native_tmp_name, L"\\\\?\\");
			elu_internal_win32_copy_utf16_string_to_extended_path(native_directory_path_length, native_tmp_name + 4, native_name);
			native_tmp_directory_path_length = native_directory_path_length + 4;
		}
		else if (native_directory_path_length > 2 && (native_name[0] == L'\\' || native_name[0] == L'/') && (native_name[1] == L'\\' || native_name[1] == L'/') && (native_name[2] != L'\\' && native_name[2] != L'/'))
		{
			elu_internal_win32_copy_utf16_string(8, native_tmp_name, L"\\\\?\\UNC\\");
			elu_internal_win32_copy_utf16_string_to_extended_path(native_directory_path_length - 2, native_tmp_name + 8, native_name + 2);
			native_tmp_directory_path_length = native_directory_path_length + 6;
		}
		else
			return EINVAL;
	}

	DWORD native_error = ERROR_FILE_EXISTS;
	for (int try_count = 0; native_error == ERROR_FILE_EXISTS; ++try_count)
	{
		if (try_count == ELU_INTERNAL_MAKE_TMP_FILE_NAME_TRY_LIMIT)
			return EEXIST;
		elu_internal_win32_make_tmp_8dot3_file_name(native_tmp_name + native_tmp_directory_path_length, try_count);
		native_error = MoveFileW(native_name, native_tmp_name) ? 0 : GetLastError();
		if (native_error && native_error != ERROR_FILE_EXISTS)
		{
			switch (native_error)
			{
				case ERROR_FILE_NOT_FOUND:
					return ENOENT;
				case ERROR_PATH_NOT_FOUND:
					return ENOENT;
				case ERROR_ACCESS_DENIED:
					return EACCES;
				case ERROR_INVALID_NAME:
					return ENOENT;
				default:
					return EIO;
			}
		}
	}

	elu_internal_win32_copy_utf16_string((size_t)(native_tmp_directory_path_length + tmp_file_name_part_length + 1), native_name_buffer, native_tmp_name);
	elu_internal_win32_object_list_t* object_list;
	error = elu_internal_win32_list_directory((size_t)(native_tmp_directory_path_length + tmp_file_name_part_length), native_name_buffer, &object_list);
	if (error)
	{
		MoveFileW(native_tmp_name, native_name);
		return error;
	}

	native_error = 0;
	elu_internal_win32_object_t* object = object_list->last;
	for (size_t n = object_list->object_count, i = 0; !native_error && i != n; object = (elu_internal_win32_object_t*)((uintptr_t)object - (object_header_size + ((size_t)object->previous_name_length * sizeof(WCHAR)))), ++i)
	{
		elu_internal_win32_copy_utf16_string((size_t)object->name_length, native_name_buffer, object->name);
		*(native_name_buffer + (size_t)object->name_length) = 0;
		if (object->flags & ELU_INTERNAL_WIN32_OBJECT_FLAG_DIRECTORY)
			native_error = RemoveDirectoryW(native_name_buffer) ? 0 : GetLastError();
		else
			native_error = DeleteFileW(native_name_buffer) ? 0 : GetLastError();
	}
	if (!native_error)
		native_error = RemoveDirectoryW(native_tmp_name) ? 0 : GetLastError();

	if (native_error)
	{
		// Very bad partial delete error. Can not complete operation or recover to old state.
		MoveFileW(native_tmp_name, native_name);
		switch (native_error)
		{
			case ERROR_FILE_NOT_FOUND:
				return ENOENT;
			case ERROR_PATH_NOT_FOUND:
				return ENOENT;
			case ERROR_ACCESS_DENIED:
				return EACCES;
			case ERROR_INVALID_NAME:
				return ENOENT;
			default:
				return EIO;
		}
	}

	return 0;
}

int elu_move_file(size_t old_name_length, const char* old_name, size_t new_name_length, const char* new_name)
{
	if (old_name_length < 1 || new_name_length < 1)
		return EINVAL;

	size_t native_old_name_size;
	int error = elu_internal_win32_encode_file_path(old_name_length, old_name, &native_old_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;
	size_t native_new_name_size;
	error = elu_internal_win32_encode_file_path(new_name_length, new_name, &native_new_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_old_name_size > 0x7FFF * sizeof(WCHAR) || native_new_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	WCHAR* native_old_name = (WCHAR*)_alloca(native_old_name_size + sizeof(WCHAR) + native_new_name_size + sizeof(WCHAR));
	error = elu_internal_win32_encode_file_path(old_name_length, old_name, &native_old_name_size, native_old_name_size, native_old_name);
	if (error)
		return error;
	WCHAR* native_new_name = (WCHAR*)((uintptr_t)native_old_name + native_old_name_size + sizeof(WCHAR));
	*(WCHAR*)((uintptr_t)native_old_name + native_old_name_size) = 0;
	error = elu_internal_win32_encode_file_path(new_name_length, new_name, &native_new_name_size, native_new_name_size, native_new_name);
	if (error)
		return error;
	*(WCHAR*)((uintptr_t)native_new_name + native_new_name_size) = 0;

	if (!MoveFileW(native_old_name, native_new_name))
	{
		DWORD native_error = GetLastError();
		switch (native_error)
		{
			case ERROR_FILE_NOT_FOUND:
				return ENOENT;
			case ERROR_PATH_NOT_FOUND:
				return ENOENT;
			case ERROR_ACCESS_DENIED:
				return EACCES;
			case ERROR_FILE_EXISTS:
				return EEXIST;
			case ERROR_INVALID_NAME:
				return ENOENT;
			default:
				return EIO;
		}
	}

	return 0;
}

int elu_move_directory(size_t old_name_length, const char* old_name, size_t new_name_length, const char* new_name)
{
	if (old_name_length < 1 || new_name_length < 1)
		return EINVAL;

	size_t native_old_name_size;
	int error = elu_internal_win32_encode_file_path(old_name_length, old_name, &native_old_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;
	size_t native_new_name_size;
	error = elu_internal_win32_encode_file_path(new_name_length, new_name, &native_new_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_old_name_size > 0x7FFF * sizeof(WCHAR) || native_new_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	WCHAR* native_old_name = (WCHAR*)_alloca(native_old_name_size + sizeof(WCHAR) + native_new_name_size + sizeof(WCHAR));
	error = elu_internal_win32_encode_file_path(old_name_length, old_name, &native_old_name_size, native_old_name_size, native_old_name);
	if (error)
		return error;
	WCHAR* native_new_name = (WCHAR*)((uintptr_t)native_old_name + native_old_name_size + sizeof(WCHAR));
	*(WCHAR*)((uintptr_t)native_old_name + native_old_name_size) = 0;
	error = elu_internal_win32_encode_file_path(new_name_length, new_name, &native_new_name_size, native_new_name_size, native_new_name);
	if (error)
		return error;
	*(WCHAR*)((uintptr_t)native_new_name + native_new_name_size) = 0;

	size_t native_old_name_length = native_old_name_size / sizeof(WCHAR);
	size_t native_path_root_directory_length = elu_internal_win32_utf16_root_directory_length(native_old_name_length, native_old_name);
	if (!native_path_root_directory_length || native_path_root_directory_length == native_old_name_length)
		return EINVAL;
	if (native_old_name[native_old_name_length - 1] == L'\\' || native_old_name[native_old_name_length - 1] == L'/')
		native_old_name[--native_old_name_length] = 0;

	size_t native_new_name_length = native_new_name_size / sizeof(WCHAR);
	native_path_root_directory_length = elu_internal_win32_utf16_root_directory_length(native_new_name_length, native_new_name);
	if (!native_path_root_directory_length || native_path_root_directory_length == native_new_name_length)
		return EINVAL;
	if (native_new_name[native_new_name_length - 1] == L'\\' || native_new_name[native_new_name_length - 1] == L'/')
		native_new_name[--native_new_name_length] = 0;

	if (!MoveFileW(native_old_name, native_new_name))
	{
		DWORD native_error = GetLastError();
		if (native_error != ERROR_PATH_NOT_FOUND)
			switch (native_error)
			{
				case ERROR_FILE_NOT_FOUND:
					return ENOENT;
				case ERROR_ACCESS_DENIED:
					return EACCES;
				case ERROR_FILE_EXISTS:
					return EEXIST;
				case ERROR_INVALID_NAME:
					return ENOENT;
				default:
					return EIO;
			}

		size_t create_directory_undo_index;
		size_t directory_part_length = elu_internal_win32_get_utf16_directory_part_length_from_path(native_new_name_length, native_new_name);
		error = directory_part_length ? elu_internal_win32_create_directory(directory_part_length, native_new_name, &create_directory_undo_index) : ENOENT;
		if (error)
			return error;

		if (!MoveFileW(native_old_name, native_new_name))
		{
			native_error = GetLastError();
			elu_internal_win32_undo_create_directory(directory_part_length, native_new_name, create_directory_undo_index);
			switch (native_error)
			{
				case ERROR_FILE_NOT_FOUND:
					return ENOENT;
				case ERROR_PATH_NOT_FOUND:
					return ENOENT;
				case ERROR_ACCESS_DENIED:
					return EACCES;
				case ERROR_FILE_EXISTS:
					return EEXIST;
				case ERROR_INVALID_NAME:
					return ENOENT;
				default:
					return EIO;
			}
		}
	}

	return 0;
}

int elu_create_directory(size_t name_length, const char* name)
{
	if (name_length < 1)
		return EINVAL;

	size_t native_name_size;
	int error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	WCHAR* native_name = (WCHAR*)_alloca(native_name_size + sizeof(WCHAR));
	error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, native_name_size, native_name);
	if (error)
		return error;
	*(WCHAR*)((uintptr_t)native_name + native_name_size) = 0;

	size_t unused_directory_create_undo_index;
	error = elu_internal_win32_create_directory(name_length, native_name, &unused_directory_create_undo_index);
	return error;
}

int elu_allocate_and_list_directory(size_t name_length, const char* name, elu_allocator_context_t* allocator_context, size_t* entry_table_size_address, elu_file_entry_t** entry_table_address, size_t* directory_count_address, size_t* file_count_address)
{
	const size_t object_header_size = (size_t)(&((const elu_internal_win32_object_t*)0)->name);

	if (name_length < 1)
		return EINVAL;

	size_t native_name_size;
	int error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, 0, 0);
	if (error != ENOBUFS)
		return error;

	if (native_name_size > 0x7FFF * sizeof(WCHAR))
		return ENAMETOOLONG;

	WCHAR* native_name_buffer = (WCHAR*)_alloca((0x7FFF + 1) * sizeof(WCHAR));
	error = elu_internal_win32_encode_file_path(name_length, name, &native_name_size, native_name_size, native_name_buffer);
	if (error)
		return error;
	*(WCHAR*)((uintptr_t)native_name_buffer + native_name_size) = 0;

	elu_internal_win32_object_list_t* object_list;
	error = elu_internal_win32_list_directory(native_name_size / sizeof(WCHAR), native_name_buffer, &object_list);
	if (error)
		return error;

	size_t directory_count = 0;
	size_t file_count = 0;
	size_t text_size = 0;
	size_t object_utf8_name_size;
	elu_internal_win32_object_t* object = object_list->first;
	for (size_t n = object_list->object_count, i = 0; i != n; object = (elu_internal_win32_object_t*)((uintptr_t)object + object_header_size + ((size_t)object->name_length * sizeof(WCHAR))), ++i)
	{
		error = elu_internal_win32_decode_file_path((size_t)object->name_length * sizeof(WCHAR), object->name, &object_utf8_name_size, 0, 0);
		if (error && error != ENOBUFS)
		{
			elu_internal_win32_deallocate_object_list(object_list);
			return error;
		}
		text_size += object_utf8_name_size + 1;
		if (object->flags & ELU_INTERNAL_WIN32_OBJECT_FLAG_DIRECTORY)
			++directory_count;
		else
			++file_count;
	}

	size_t required_size = ((directory_count + file_count) * sizeof(elu_file_entry_t)) + text_size;
	elu_file_entry_t* buffer = allocator_context->allocator_procedure(allocator_context->context, required_size);
	if (!buffer)
	{
		elu_internal_win32_deallocate_object_list(object_list);
		return ENOBUFS;
	}

	size_t write_offset = (directory_count + file_count) * sizeof(elu_file_entry_t);
	object = object_list->first;
	for (size_t i = 0; i != directory_count; object = (elu_internal_win32_object_t*)((uintptr_t)object + object_header_size + ((size_t)object->name_length * sizeof(WCHAR))))
		if (object->flags & ELU_INTERNAL_WIN32_OBJECT_FLAG_DIRECTORY)
		{
			if (write_offset == required_size)
			{
				allocator_context->deallocator_procedure(allocator_context->context, required_size, buffer);
				elu_internal_win32_deallocate_object_list(object_list);
				return EIO;
			}
			buffer[i].name = (char*)((uintptr_t)buffer + write_offset);
			error = elu_internal_win32_decode_file_path((size_t)object->name_length * sizeof(WCHAR), object->name, &object_utf8_name_size, required_size - (write_offset + 1), buffer[i].name);
			if (error)
			{
				allocator_context->deallocator_procedure(allocator_context->context, required_size, buffer);
				elu_internal_win32_deallocate_object_list(object_list);
				return error;
			}
			buffer[i].name_length = object_utf8_name_size;
			*(buffer[i].name + object_utf8_name_size) = 0;
			write_offset += object_utf8_name_size + 1;
			++i;
		}

	object = object_list->first;
	for (size_t i = 0; i != file_count; object = (elu_internal_win32_object_t*)((uintptr_t)object + object_header_size + ((size_t)object->name_length * sizeof(WCHAR))))
		if (!(object->flags & ELU_INTERNAL_WIN32_OBJECT_FLAG_DIRECTORY))
		{
			if (write_offset == required_size)
			{
				allocator_context->deallocator_procedure(allocator_context->context, required_size, buffer);
				elu_internal_win32_deallocate_object_list(object_list);
				return EIO;
			}
			buffer[directory_count + i].name = (char*)((uintptr_t)buffer + write_offset);
			error = elu_internal_win32_decode_file_path((size_t)object->name_length * sizeof(WCHAR), object->name, &object_utf8_name_size, required_size - (write_offset + 1), buffer[directory_count + i].name);
			if (error)
			{
				allocator_context->deallocator_procedure(allocator_context->context, required_size, buffer);
				elu_internal_win32_deallocate_object_list(object_list);
				return error;
			}
			buffer[directory_count + i].name_length = object_utf8_name_size;
			*(buffer[directory_count + i].name + object_utf8_name_size) = 0;
			write_offset += object_utf8_name_size + 1;
			++i;
		}

	elu_internal_win32_deallocate_object_list(object_list);
	*entry_table_size_address = required_size;
	*entry_table_address = buffer;
	*directory_count_address = directory_count;
	*file_count_address = file_count;
	return 0;
}

int elu_get_executable_file_name(size_t buffer_size, char* buffer, size_t* file_name_length_address)
{
	WCHAR* native_name = (WCHAR*)_alloca((0x7FFF + 1) * sizeof(WCHAR));
	size_t native_name_length = (size_t)GetModuleFileNameW(0, native_name, 0x7FFF + 1);
	if (!native_name_length || native_name_length > 0x7FFF)
		return EIO;

	return elu_internal_win32_decode_file_path(native_name_length * sizeof(WCHAR), native_name, file_name_length_address, buffer_size, buffer);
}

int elu_allocate_and_get_executable_file_name(elu_allocator_context_t* allocator_context, char** file_name_address, size_t* file_name_length_address)
{
	WCHAR* native_name = (WCHAR*)_alloca((0x7FFF + 1) * sizeof(WCHAR));
	size_t native_name_length = (size_t)GetModuleFileNameW(0, native_name, 0x7FFF + 1);
	if (!native_name_length || native_name_length > 0x7FFF)
		return EIO;

	int error = elu_internal_win32_decode_file_path(native_name_length * sizeof(WCHAR), native_name, file_name_length_address, 0, 0);
	if (error != ENOBUFS)
		return error ? error : EIO;

	char* file_name = (char*)allocator_context->allocator_procedure(allocator_context->context, *file_name_length_address);
	if (!file_name)
		return ENOBUFS;

	error = elu_internal_win32_decode_file_path(native_name_length * sizeof(WCHAR), native_name, file_name_length_address, *file_name_length_address, file_name);
	if (error)
	{
		allocator_context->deallocator_procedure(allocator_context->context, *file_name_length_address, file_name);
		return error;
	}

	return 0;
}

int elu_get_program_directory(size_t buffer_size, char* buffer, size_t* directory_name_length_address)
{
	WCHAR* native_name = (WCHAR*)_alloca(0x8000 * sizeof(WCHAR));
	size_t native_name_length = (size_t)GetModuleFileNameW(0, native_name, 0x7FFF + 1);
	if (!native_name_length || native_name_length > 0x7FFF)
		return EIO;

	size_t directory_part_length = 0;
	if (native_name_length)
	{
		size_t root_length = elu_internal_win32_utf16_root_directory_length(native_name_length, native_name);
		for (size_t index = directory_part_length - 1; index != root_length; --index)
			if (native_name[index] == L'\\' || native_name[index] == L'/')
			{
				directory_part_length = index;
				break;
			}
		if (!directory_part_length)
		{
			directory_part_length = root_length;
			if (directory_part_length && native_name[directory_part_length - 1] == L'\\' || native_name[directory_part_length - 1] == L'/')
				--directory_part_length;
		}
	}
	if (!directory_part_length)
		return EIO;

	return elu_internal_win32_decode_file_path(directory_part_length * sizeof(WCHAR), native_name, directory_name_length_address, buffer_size, buffer);
}

int elu_allocate_and_get_program_directory(elu_allocator_context_t* allocator_context, char** directory_name_address, size_t* directory_name_length_address)
{
	WCHAR* native_name = (WCHAR*)_alloca(0x8000 * sizeof(WCHAR));
	size_t native_name_length = (size_t)GetModuleFileNameW(0, native_name, 0x7FFF + 1);
	if (!native_name_length || native_name_length > 0x7FFF)
		return EIO;

	size_t directory_part_length = 0;
	if (native_name_length)
	{
		size_t root_length = elu_internal_win32_utf16_root_directory_length(native_name_length, native_name);
		for (size_t index = directory_part_length - 1; index != root_length; --index)
			if (native_name[index] == L'\\' || native_name[index] == L'/')
			{
				directory_part_length = index;
				break;
			}
		if (!directory_part_length)
		{
			directory_part_length = root_length;
			if (directory_part_length && native_name[directory_part_length - 1] == L'\\' || native_name[directory_part_length - 1] == L'/')
				--directory_part_length;
		}
	}
	if (!directory_part_length)
		return EIO;

	size_t program_directory_name_length;
	int error = elu_internal_win32_decode_file_path(directory_part_length * sizeof(WCHAR), native_name, &program_directory_name_length, 0, 0);
	*directory_name_length_address = program_directory_name_length;
	if (error != ENOBUFS)
		return error;

	char* buffer = (char*)allocator_context->allocator_procedure(allocator_context->context, program_directory_name_length);
	if (!buffer)
		return ENOBUFS;

	error = elu_internal_win32_decode_file_path(directory_part_length * sizeof(WCHAR), native_name, directory_name_length_address, program_directory_name_length, buffer);
	if (error)
	{
		allocator_context->deallocator_procedure(allocator_context->context, program_directory_name_length, buffer);
		return EIO;
	}

	*directory_name_address = buffer;
	return 0;
}

int elu_get_data_directory(size_t buffer_size, size_t sub_directory_name_length, const char* sub_directory_name, char* buffer, size_t* directory_name_length_address)
{
	WCHAR* native_name = (WCHAR*)_alloca((0x7FFF + 1) * sizeof(WCHAR));
	size_t native_name_length = (size_t)GetEnvironmentVariableW(L"LOCALAPPDATA", native_name, 0x7FFF + 1);
	
	if (!native_name_length || native_name_length > 0x7FFF)
	{
		HMODULE Userenv = LoadLibraryW(L"Userenv.dll");
		if (!Userenv)
			return ENOSYS;

		BOOL (WINAPI* Userenv_GetUserProfileDirectoryW)(HANDLE hToken, WCHAR* lpProfileDir, DWORD* lpcchSize) = (BOOL (WINAPI*)(HANDLE, WCHAR*, DWORD*))GetProcAddress(Userenv, "GetUserProfileDirectoryW");
		if (!Userenv_GetUserProfileDirectoryW)
		{
			FreeLibrary(Userenv);
			return ENOSYS;
		}

		DWORD user_diectory_name_length = 0x7FFF + 1;
		if (!Userenv_GetUserProfileDirectoryW(GetCurrentProcessToken(), native_name, &user_diectory_name_length))
		{
			FreeLibrary(Userenv);
			return ENOSYS;
		}
		native_name_length = elu_internal_win32_utf16_string_length(native_name);

		FreeLibrary(Userenv);
	}

	if (native_name_length && (native_name[native_name_length - 1] == L'\\' || native_name[native_name_length - 1] == L'/'))
		--native_name_length;

	size_t base_directory_name_length;
	int error = elu_internal_win32_decode_file_path(native_name_length * sizeof(WCHAR), native_name, &base_directory_name_length, 0, 0);
	if (error != ENOBUFS)
		return error;

	size_t data_directory_name_length = base_directory_name_length + 1 + sub_directory_name_length;
	*directory_name_length_address = data_directory_name_length;
	if (data_directory_name_length > buffer_size)
		return ENOBUFS;

	error = elu_internal_win32_decode_file_path(native_name_length * sizeof(WCHAR), native_name, &base_directory_name_length, base_directory_name_length, buffer);
	if (error)
		return error;
	*(buffer + base_directory_name_length) = '\\';
	elu_internal_copy_utf8_string(sub_directory_name_length, buffer + base_directory_name_length + 1, sub_directory_name);

	return 0;
}

int elu_allocate_and_get_data_directory(elu_allocator_context_t* allocator_context, size_t sub_directory_name_length, const char* sub_directory_name, char** directory_name_address, size_t* directory_name_length_address)
{
	WCHAR* native_name = (WCHAR*)_alloca((0x7FFF + 1) * sizeof(WCHAR));
	size_t native_name_length = (size_t)GetEnvironmentVariableW(L"LOCALAPPDATA", native_name, 0x7FFF + 1);

	if (!native_name_length || native_name_length > 0x7FFF)
	{
		HMODULE Userenv = LoadLibraryW(L"Userenv.dll");
		if (!Userenv)
			return ENOSYS;

		BOOL(WINAPI * Userenv_GetUserProfileDirectoryW)(HANDLE hToken, WCHAR * lpProfileDir, DWORD * lpcchSize) = (BOOL(WINAPI*)(HANDLE, WCHAR*, DWORD*))GetProcAddress(Userenv, "GetUserProfileDirectoryW");
		if (!Userenv_GetUserProfileDirectoryW)
		{
			FreeLibrary(Userenv);
			return ENOSYS;
		}

		DWORD user_diectory_name_length = 0x7FFF + 1;
		if (!Userenv_GetUserProfileDirectoryW(GetCurrentProcessToken(), native_name, &user_diectory_name_length))
		{
			FreeLibrary(Userenv);
			return ENOSYS;
		}
		native_name_length = elu_internal_win32_utf16_string_length(native_name);

		FreeLibrary(Userenv);
	}

	if (native_name_length && (native_name[native_name_length - 1] == L'\\' || native_name[native_name_length - 1] == L'/'))
		--native_name_length;

	size_t base_directory_name_length;
	int error = elu_internal_win32_decode_file_path(native_name_length * sizeof(WCHAR), native_name, &base_directory_name_length, 0, 0);
	if (error != ENOBUFS)
		return error;

	size_t data_directory_name_length = base_directory_name_length + 1 + sub_directory_name_length;
	*directory_name_length_address = data_directory_name_length;
	
	char* directory_name = allocator_context->allocator_procedure(allocator_context->context, data_directory_name_length);
	if (!directory_name)
		return ENOBUFS;

	error = elu_internal_win32_decode_file_path(native_name_length * sizeof(WCHAR), native_name, &base_directory_name_length, base_directory_name_length, directory_name);
	if (error)
	{
		allocator_context->deallocator_procedure(allocator_context->context, data_directory_name_length, directory_name);
		return error;
	}
	*(directory_name + base_directory_name_length) = '\\';
	elu_internal_copy_utf8_string(sub_directory_name_length, directory_name + base_directory_name_length + 1, sub_directory_name);

	*directory_name_address = directory_name;
	return 0;
}

int elu_make_path(size_t parent_directory_length, const char* parent_directory, size_t sub_directory_length, const char* sub_directory, size_t buffer_size, char* buffer, size_t* directory_name_length_address)
{
	if (parent_directory_length)
	{
		if ((parent_directory_length && (parent_directory[parent_directory_length - 1] == L'\\' || parent_directory[parent_directory_length - 1] == L'/')) &&
			(sub_directory_length || elu_internal_utf8_root_directory_length(parent_directory_length, parent_directory) != parent_directory_length))
			--parent_directory_length;

		int add_slash = (int)(parent_directory_length && sub_directory_length);
		size_t name_length = (size_t)parent_directory_length + add_slash + sub_directory_length;
		*directory_name_length_address = name_length;
		if (name_length > buffer_size)
			return ENOBUFS;

		elu_internal_copy_utf8_string(parent_directory_length, buffer, parent_directory);
		if (add_slash)
			*(buffer + parent_directory_length) = '\\';
		elu_internal_copy_utf8_string(sub_directory_length, buffer + parent_directory_length + add_slash, sub_directory);
		return 0;
	}
	else
	{
		if (elu_internal_utf8_root_directory_length(sub_directory_length, sub_directory))
		{
			*directory_name_length_address = sub_directory_length;
			if (sub_directory_length > buffer_size)
				return ENOBUFS;

			elu_internal_copy_utf8_string(sub_directory_length, buffer, sub_directory);
			return 0;
		}
		else
		{
			const size_t int_max_value = (size_t)(((unsigned int)~0) >> 1);

			if (sub_directory_length < 1 || sub_directory_length > int_max_value)
				return EINVAL;

			size_t native_name_size;
			int error = elu_internal_win32_encode_file_path(sub_directory_length, sub_directory, &native_name_size, 0, 0);
			if (error != ENOBUFS)
				return error;

			if (native_name_size > 0x7FFF * sizeof(WCHAR))
				return ENAMETOOLONG;

			WCHAR* native_name_buffer = (WCHAR*)_alloca((native_name_size + 1) * sizeof(WCHAR));
			error = elu_internal_win32_encode_file_path(sub_directory_length, sub_directory, &native_name_size, native_name_size, native_name_buffer);
			if (error)
				return error;
			*(WCHAR*)((uintptr_t)native_name_buffer + native_name_size) = 0;

			size_t native_path_length = (size_t)GetFullPathNameW(native_name_buffer, 0, 0, 0) - 1;
			if (native_path_length == (size_t)~0 || !native_path_length)
				return EIO;

			if (native_path_length > 0x7FFF)
				return ENAMETOOLONG;

			WCHAR* absolute_native_path = (WCHAR*)_alloca((native_path_length + 1) * sizeof(WCHAR));
			if ((size_t)GetFullPathNameW(native_name_buffer, (DWORD)(native_path_length + 1), absolute_native_path, 0) != native_path_length)
				return EIO;

			return elu_internal_win32_decode_file_path(native_path_length, absolute_native_path, directory_name_length_address, buffer_size, buffer);
		}
	}
}

int elu_allocate_and_make_path(elu_allocator_context_t* allocator_context, size_t parent_directory_length, const char* parent_directory, size_t sub_directory_length, const char* sub_directory, char** directory_name_address, size_t* directory_name_length_address)
{
	if (parent_directory_length)
	{
		if ((parent_directory_length && (parent_directory[parent_directory_length - 1] == L'\\' || parent_directory[parent_directory_length - 1] == L'/')) &&
			(sub_directory_length || elu_internal_utf8_root_directory_length(parent_directory_length, parent_directory) != parent_directory_length))
			--parent_directory_length;

		int add_slash = (int)(parent_directory_length && sub_directory_length);
		size_t name_length = (size_t)parent_directory_length + add_slash + sub_directory_length;
		*directory_name_length_address = name_length;

		char* buffer = (char*)allocator_context->allocator_procedure(allocator_context->context, name_length);
		if (!buffer)
			return ENOBUFS;

		elu_internal_copy_utf8_string(parent_directory_length, buffer, parent_directory);
		if (add_slash)
			*(buffer + parent_directory_length) = '\\';
		elu_internal_copy_utf8_string(sub_directory_length, buffer + parent_directory_length + add_slash, sub_directory);
		*directory_name_address = buffer;
		return 0;
	}
	else
	{
		if (elu_internal_utf8_root_directory_length(sub_directory_length, sub_directory))
		{
			*directory_name_length_address = sub_directory_length;
			char* buffer = (char*)allocator_context->allocator_procedure(allocator_context->context, sub_directory_length);
			if (!buffer)
				return ENOBUFS;

			elu_internal_copy_utf8_string(sub_directory_length, buffer, sub_directory);
			*directory_name_address = buffer;
			return 0;
		}
		else
		{
			const size_t int_max_value = (size_t)(((unsigned int)~0) >> 1);

			if (sub_directory_length < 1 || sub_directory_length > int_max_value)
				return EINVAL;

			size_t native_name_size;
			int error = elu_internal_win32_encode_file_path(sub_directory_length, sub_directory, &native_name_size, 0, 0);
			if (error != ENOBUFS)
				return error;

			if (native_name_size > 0x7FFF * sizeof(WCHAR))
				return ENAMETOOLONG;

			WCHAR* native_name_buffer = (WCHAR*)_alloca((native_name_size + 1) * sizeof(WCHAR));
			error = elu_internal_win32_encode_file_path(sub_directory_length, sub_directory, &native_name_size, native_name_size, native_name_buffer);
			if (error)
				return error;
			*(WCHAR*)((uintptr_t)native_name_buffer + native_name_size) = 0;

			size_t native_path_length = (size_t)GetFullPathNameW(native_name_buffer, 0, 0, 0) - 1;
			if (native_path_length == (size_t)~0 || !native_path_length)
				return EIO;

			if (native_path_length > 0x7FFF)
				return ENAMETOOLONG;

			WCHAR* absolute_native_path = (WCHAR*)_alloca((native_path_length + 1) * sizeof(WCHAR));
			if ((size_t)GetFullPathNameW(native_name_buffer, (DWORD)(native_path_length + 1), absolute_native_path, 0) != native_path_length)
				return EIO;

			size_t allocated_buffer_size;
			error = elu_internal_win32_decode_file_path(native_path_length, absolute_native_path, &allocated_buffer_size, 0, 0);
			if (error != ENOBUFS)
				return error;

			*directory_name_length_address = allocated_buffer_size;
			char* buffer = (char*)allocator_context->allocator_procedure(allocator_context->context, allocated_buffer_size);
			if (!buffer)
				return ENOBUFS;

			error = elu_internal_win32_decode_file_path(native_path_length, absolute_native_path, directory_name_length_address, allocated_buffer_size, buffer);
			if (error)
			{
				allocator_context->deallocator_procedure(allocator_context->context, allocated_buffer_size, buffer);
				return error;
			}
			if (*directory_name_length_address != allocated_buffer_size)
			{
				error = EIO;
				allocator_context->deallocator_procedure(allocator_context->context, allocated_buffer_size, buffer);
				return error;
			}

			*directory_name_address = buffer;
			return 0;
		}
	}
}

#ifdef _MSC_VER
#pragma warning( pop )
#endif // _MSC_VER

#ifdef __cplusplus
}
#endif // __cplusplus