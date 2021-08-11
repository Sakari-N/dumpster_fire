/*
	Directory Delta Tool authored by archiver Sakari N.

	Description

		The Directory Delta Tool can be used to compare contenst of two directories.

		This tool is used by passing two directory paths after the executable path in process arguments.
		The command to run this program looks like the following "<program path> <directory A path> <directory B path>".
		These two directories will be compared and the difference between them reported to the user.
		The difference is reported in similar way to result of mathematical subtraction where boths sides contain multiple variables.

		Note: Soft links are currently ignored. The elu_list_directory function will probably be changed to support these at some point,
		but in comparing directories it might be good idea to just ignore them or compare the paths in the soft links and not the linked content.

		Also all the MSVC nonsense needs to be placed behind _MSC_VER.

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

#ifndef _WIN64
#error Unsupported platform
#endif

//#define DIRECTORY_DELTA_DEBUG_TIMERS

#include <Windows.h>
#include "elu_error.h"
#include "elu_process_arguments.h"
#include "elu_file_api.h"
#include "elu_std_io.h"
#include "elu_win32_x64_crt_base.h"
#ifdef _DEBUG
static void assert(int condition)
{
	// remember to pass /NODEFAULTLIB you filthy casual.
	if (condition)
		return;
	*(volatile int*)0 = 0;
	return;
}
#endif // _DEBUG

#ifdef _MSC_VER
#pragma warning( push )

// Buffer read/write overrun. The Microsoft C/C++ compiler is so wrong about these that it is not even funny
#pragma warning( disable : 6385)
#pragma warning( disable : 6386)

#endif // _MSC_VER

#define ANY_ALLOCATOR_CONTEXT (void*)0

uint32_t crc32(size_t data_size, const void* data)
{
	static const uint32_t lookup_table[256] = {
		0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
		0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
		0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
		0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
		0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
		0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
		0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
		0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
		0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
		0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
		0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
		0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
		0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
		0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
		0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
		0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
		0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
		0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
		0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
		0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
		0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
		0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
		0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
		0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
		0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
		0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
		0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
		0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
		0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
		0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
		0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
		0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D };
	uint32_t hash = 0xFFFFFFFF;
	for (const uint8_t* read = (const uint8_t*)data, *read_end = read + data_size; read != read_end; ++read)
		hash = lookup_table[(uint32_t)*read ^ (hash & 0xFF)] ^ (hash >> 8);
	return ~hash;
}

static size_t get_page_size()
{
	SYSTEM_INFO system_info;
	GetSystemInfo(&system_info);
	return (size_t)system_info.dwPageSize;
}

static void* allocator_callback(void* context, size_t size)
{
	size_t page_size = get_page_size();
	size_t allocation_size = (size + (page_size - 1)) & ~(page_size - 1);
	return (void*)VirtualAlloc(0, allocation_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

static void deallocator_callback(void* context, size_t size, void* allocation)
{
	VirtualFree(allocation, 0, MEM_RELEASE);
}

static int write_number_to_std_output(size_t number)
{
	char buffer[32];
	int length = 0;
	while (number || !length)
	{
		buffer[((sizeof(buffer) / sizeof(*buffer)) - 1) - (size_t)length] = (char)((int)'0' + (int)(number % 10));
		number /= 10;
		++length;
	}

	return elu_write_std_io((size_t)length, buffer + (sizeof(buffer) / sizeof(*buffer)) - length);
}

static int write_error_to_std_output(int code)
{
	size_t length;
	const char* name;
	elu_get_error_name(code, &length, &name);
	return elu_write_std_io(length, name);
}

static size_t root_directory_length(size_t path_langth, const char* path)
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

static int are_absolute_paths_in_same_volume(size_t left_length, const char* left, size_t right_length, const char* right)
{
	size_t left_root_length = root_directory_length(left_length, left);
	size_t right_root_length = root_directory_length(right_length, right);
	return (left_root_length && right_root_length) && (left_root_length == right_root_length) && !memcmp(left, right, left_root_length);
}

static int create_thread(LPTHREAD_START_ROUTINE thread_start_routine, void* thread_parameter, HANDLE* thread_handle_address)
{
	HANDLE current_thread = GetCurrentThread();
	int current_thread_priority = GetThreadPriority(current_thread);

	HANDLE thread_handle = CreateThread(0, 0, thread_start_routine, thread_parameter, 0, 0);
	if (!thread_handle)
		return EIO;

	if (current_thread_priority != THREAD_PRIORITY_ERROR_RETURN)
		SetThreadPriority(thread_handle, current_thread_priority);

	*thread_handle_address = thread_handle;
	return 0;
}

typedef struct crc_at_index_t
{
	uint32_t crc32;
	size_t index;
} crc_at_index_t;

static void sort_crc_at_index_table(size_t length, crc_at_index_t* table)
{
	size_t j = (length - 1) >> 1;
	if (table[length - 1].crc32 < table[0].crc32)
	{
		crc_at_index_t t = table[length - 1];
		table[length - 1] = table[0];
		table[0] = t;
	}
	if (table[j].crc32 < table[0].crc32)
	{
		crc_at_index_t t = table[j];
		table[j] = table[0];
		table[0] = t;
	}
	if (table[length - 1].crc32 < table[j].crc32)
	{
		crc_at_index_t t = table[length - 1];
		table[length - 1] = table[j];
		table[j] = t;
	}
	uint32_t x = table[j].crc32;

	j = length;
	for (size_t i = (size_t)~0;;)
	{
		while (table[--j].crc32 > x)
			continue;
		while (table[++i].crc32 < x)
			continue;
		if (i < j)
		{
			crc_at_index_t t = table[i];
			table[i] = table[j];
			table[j] = t;
		}
		else
			break;
	}
	++j;

	if (j > 1)
		sort_crc_at_index_table(j, table);
	if (length - j > 1)
		sort_crc_at_index_table(length - j, table + j);
}

#define LIST_SHARED_PATH_FLAG 0x00000001
#define LIST_FILE_PATH_FLAG 0x00000002
#define LIST_CONTENT_EQUAL_FLAG 0x00000004

typedef struct list_directory_data_t
{
	elu_allocator_context_t* allocator_context;
	size_t directory_length;
	const char* directory;
	int sort_by_crc32;
	int error;
	size_t count;
	struct
	{
		uint32_t crc32;
		uint32_t flags;
		size_t path_pair_index;
		size_t length;
		char* path;
	}* table;
} list_directory_data_t;

static void list_directory(list_directory_data_t* parameter)
{
	size_t page_size = get_page_size();

	size_t path_table_size;
	size_t directory_path_count;
	size_t file_path_count;
	elu_file_entry_t* path_table;
	int error = elu_allocate_and_list_directory(parameter->directory_length, parameter->directory, parameter->allocator_context, &path_table_size, &path_table, &directory_path_count, &file_path_count);
	if (error)
	{
		parameter->error = error;
		return;
	}
	size_t path_count = directory_path_count + file_path_count;

	size_t path_text_data_size = 0;
	for (size_t i = 0; i != path_count; ++i)
	{
#ifdef _DEBUG
		assert(path_table[i].name_length >= (parameter->directory_length + 1));
#endif // _DEBUG
		path_text_data_size += path_table[i].name_length - (parameter->directory_length + 1) + 1;
	}

	if (parameter->sort_by_crc32)
	{
		crc_at_index_t* crc_table = (crc_at_index_t*)VirtualAlloc(0, ((path_count * sizeof(crc_at_index_t)) + (page_size - 1)) & ~(page_size - 1), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!crc_table)
		{
			parameter->allocator_context->deallocator_procedure(parameter->allocator_context->context, path_table_size, path_table);
			parameter->error = ENOMEM;
			return;
		}
		for (size_t i = 0; i != path_count; ++i)
		{
			crc_table[i].crc32 = crc32(path_table[i].name_length - (parameter->directory_length + 1), (const void*)(path_table[i].name + (parameter->directory_length + 1)));
			crc_table[i].index = i;
		}
		sort_crc_at_index_table(path_count, crc_table);

		*(void**)&parameter->table = (void*)VirtualAlloc(0, ((path_count * sizeof(*((const list_directory_data_t*)0)->table) + path_text_data_size) + (page_size - 1)) & ~(page_size - 1), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!parameter->table)
		{
			VirtualFree(crc_table, 0, MEM_RELEASE);
			parameter->allocator_context->deallocator_procedure(parameter->allocator_context->context, path_table_size, path_table);
			parameter->error = ENOMEM;
			return;
		}
		for (size_t p = path_count * sizeof(*((const list_directory_data_t*)0)->table), i = 0; i != path_count; p += path_table[crc_table[i].index].name_length - (parameter->directory_length + 1) + 1, ++i)
		{
#ifdef _DEBUG
			assert(p < (path_count * sizeof(*((const list_directory_data_t*)0)->table) + path_text_data_size));
#endif // _DEBUG
			parameter->table[i].crc32 = crc_table[i].crc32;
			parameter->table[i].flags = (crc_table[i].index < directory_path_count) ? LIST_FILE_PATH_FLAG: 0;
			parameter->table[i].path_pair_index = (size_t)~0;
			parameter->table[i].length = path_table[crc_table[i].index].name_length - (parameter->directory_length + 1);
			parameter->table[i].path = (char*)((uintptr_t)parameter->table + p);
			memcpy(parameter->table[i].path, path_table[crc_table[i].index].name + (parameter->directory_length + 1), path_table[crc_table[i].index].name_length - (parameter->directory_length + 1) + 1);
		}
		VirtualFree(crc_table, 0, MEM_RELEASE);
	}
	else
	{
		*(void**)&parameter->table = (void*)VirtualAlloc(0, ((path_count * sizeof(*((const list_directory_data_t*)0)->table) + path_text_data_size) + (page_size - 1)) & ~(page_size - 1), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!parameter->table)
		{
			parameter->allocator_context->deallocator_procedure(parameter->allocator_context->context, path_table_size, path_table);
			parameter->error = ENOMEM;
			return;
		}
		for (size_t p = path_count * sizeof(*((const list_directory_data_t*)0)->table), i = 0; i != path_count; p += path_table[i].name_length - (parameter->directory_length + 1) + 1, ++i)
		{
#ifdef _DEBUG
			assert(p < (path_count * sizeof(*((const list_directory_data_t*)0)->table) + path_text_data_size));
#endif // _DEBUG
			parameter->table[i].crc32 = crc32(path_table[i].name_length - (parameter->directory_length + 1), (const void*)(path_table[i].name + (parameter->directory_length + 1)));
			parameter->table[i].flags = (i < directory_path_count) ? LIST_FILE_PATH_FLAG : 0;
			parameter->table[i].path_pair_index = (size_t)~0;
			parameter->table[i].length = path_table[i].name_length - (parameter->directory_length + 1);
			parameter->table[i].path = (char*)((uintptr_t)parameter->table + p);
			memcpy(parameter->table[i].path, path_table[i].name + (parameter->directory_length + 1), path_table[i].name_length - (parameter->directory_length + 1) + 1);
		}
	}

	parameter->allocator_context->deallocator_procedure(parameter->allocator_context->context, path_table_size, path_table);

	parameter->count = path_count;

	parameter->error = 0;
}

static DWORD CALLBACK list_directory_thread_routine(void* parameter)
{
	list_directory((list_directory_data_t*)parameter);
	ExitThread(0);
	return 0;
}

static size_t find_path_from_list_directory_data(const list_directory_data_t* list_directory_data, size_t path_lenght, const char* path)
{
	size_t index = (size_t)~0;
	uint32_t path_crc32 = crc32(path_lenght, (const void*)path);

	for (size_t bottom = 0, top = list_directory_data->count - 1; bottom <= top;)
	{
		size_t middle = (bottom + top) >> 1;
		if (list_directory_data->table[middle].crc32 < path_crc32)
			bottom = middle + 1;
		else if (list_directory_data->table[middle].crc32 > path_crc32)
		{
			top = middle - 1;
			if (top == (size_t)~0)
				break;
		}
		else
		{
			index = middle;
			break;
		}
	}

	if (index == (size_t)~0)
		return (size_t)~0;

	while (index && list_directory_data->table[index - 1].crc32 == path_crc32)
		--index;

	while (index != list_directory_data->count && list_directory_data->table[index].crc32 == path_crc32)
	{
		if (list_directory_data->table[index].length == path_lenght && !memcmp(list_directory_data->table[index].path, path, path_lenght))
			return index;
		++index;
	}

	return (size_t)~0;
}

#define LEFT_INDEX 0
#define RIGHT_INDEX 1

static int directory_delta(int extended_report, elu_allocator_context_t* allocator_context, size_t left_directory_length, const char* left_directory, size_t right_directory_length, const char* right_directory)
{
	const size_t asynchronous_io_request_size_limit = (size_t)0x40000000;

	elu_write_std_io(21, "Comparing directory \"");
	elu_write_std_io(left_directory_length, left_directory);
	elu_write_std_io(6, "\" to \"");
	elu_write_std_io(right_directory_length, right_directory);
	elu_write_std_io(3, "\".\n");

	elu_write_std_io(34, "Enumerating directory contents...\n");

	size_t page_size = get_page_size();
	int error = 0;
	list_directory_data_t left_list_directory_data;
	left_list_directory_data.allocator_context = allocator_context;
	list_directory_data_t right_list_directory_data;
	right_list_directory_data.allocator_context = allocator_context;
	int shared_volume = are_absolute_paths_in_same_volume(left_directory_length, left_directory, right_directory_length, right_directory);
	if (shared_volume)
	{
		left_list_directory_data.directory_length = left_directory_length;
		left_list_directory_data.directory = left_directory;
		left_list_directory_data.sort_by_crc32 = 0;
		list_directory(&left_list_directory_data);
		error = left_list_directory_data.error;
		if (error)
		{
			elu_write_std_io(13, "Enumerating \"");
			elu_write_std_io(left_directory_length, left_directory);
			elu_write_std_io(20, "\" failed with error ");
			write_error_to_std_output(error);
			elu_write_std_io(2, ".\n");

			return error;
		}
		right_list_directory_data.directory_length = right_directory_length;
		right_list_directory_data.directory = right_directory;
		right_list_directory_data.sort_by_crc32 = 1;
		list_directory(&right_list_directory_data);
		error = right_list_directory_data.error;
		if (error)
		{
			elu_write_std_io(13, "Enumerating \"");
			elu_write_std_io(right_directory_length, right_directory);
			elu_write_std_io(20, "\" failed with error ");
			write_error_to_std_output(error);
			elu_write_std_io(2, ".\n");

			VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
			return error;
		}
	}
	else
	{
		volatile list_directory_data_t* shared_right_list_directory_data = (volatile list_directory_data_t*)VirtualAlloc(0, (sizeof(list_directory_data_t) + (page_size - 1)) & ~(page_size - 1), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!shared_right_list_directory_data)
		{
			error = ENOMEM;

			elu_write_std_io(42, "Enumerating directories failed with error ");
			write_error_to_std_output(error);
			elu_write_std_io(2, ".\n");

			return error;
		}
		shared_right_list_directory_data->allocator_context = allocator_context;
		shared_right_list_directory_data->directory_length = right_directory_length;
		shared_right_list_directory_data->directory = right_directory;
		shared_right_list_directory_data->sort_by_crc32 = 1;
		HANDLE right_list_thread_handle;
		error = create_thread(list_directory_thread_routine, (void*)shared_right_list_directory_data, &right_list_thread_handle);
		if (error)
		{
			elu_write_std_io(13, "Enumerating \"");
			elu_write_std_io(right_directory_length, right_directory);
			elu_write_std_io(20, "\" failed with error ");
			write_error_to_std_output(error);
			elu_write_std_io(2, ".\n");

			VirtualFree((void*)shared_right_list_directory_data, 0, MEM_RELEASE);
			return error;
		}
		left_list_directory_data.directory_length = left_directory_length;
		left_list_directory_data.directory = left_directory;
		left_list_directory_data.sort_by_crc32 = 0;
		list_directory(&left_list_directory_data);
		error = left_list_directory_data.error;
		while (WaitForSingleObject(right_list_thread_handle, INFINITE) != WAIT_OBJECT_0)
			continue;
		CloseHandle(right_list_thread_handle);
		if (error)
		{
			elu_write_std_io(13, "Enumerating \"");
			elu_write_std_io(left_directory_length, left_directory);
			elu_write_std_io(20, "\" failed with error ");
			write_error_to_std_output(error);
			elu_write_std_io(2, ".\n");

			VirtualFree((void*)shared_right_list_directory_data, 0, MEM_RELEASE);
			return error;
		}
		memcpy((void*)&right_list_directory_data, (const void*)shared_right_list_directory_data, sizeof(list_directory_data_t));
		VirtualFree((void*)shared_right_list_directory_data, 0, MEM_RELEASE);
		error = right_list_directory_data.error;
		if (error)
		{
			elu_write_std_io(13, "Enumerating \"");
			elu_write_std_io(right_directory_length, right_directory);
			elu_write_std_io(20, "\" failed with error ");
			write_error_to_std_output(error);
			elu_write_std_io(2, ".\n");

			VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
			return error;
		}
	}

	size_t longest_name_length = 0;
	size_t match_count = 0;
	size_t left_delta_count = 0;
	for (size_t n = left_list_directory_data.count, i = 0; i != n; ++i)
	{
		if (longest_name_length < left_list_directory_data.table[i].length)
			longest_name_length = left_list_directory_data.table[i].length;
		size_t right_index = find_path_from_list_directory_data(&right_list_directory_data, left_list_directory_data.table[i].length, left_list_directory_data.table[i].path);
		if (right_index != (size_t)~0)
		{
			left_list_directory_data.table[i].flags |= LIST_SHARED_PATH_FLAG;
			left_list_directory_data.table[i].path_pair_index = right_index;
			right_list_directory_data.table[right_index].flags |= LIST_SHARED_PATH_FLAG;
			right_list_directory_data.table[right_index].path_pair_index = i;
			++match_count;
		}
		else
			++left_delta_count;
	}
	size_t right_delta_count = right_list_directory_data.count - match_count;
	for (size_t n = right_list_directory_data.count, i = 0; i != n; ++i)
	{
		if (longest_name_length < right_list_directory_data.table[i].length)
			longest_name_length = right_list_directory_data.table[i].length;
	}

	elu_write_std_io(45, "Enumerating directories succeeded.\nComparing ");
	write_number_to_std_output(match_count);
	elu_write_std_io(36, " files with equal relative paths...\n");

	// Only for statistic, not for correct functionality. Only completed IO is counted.
	size_t statistical_byte_read_count = 0;

	size_t equal_file_count = 0;

	size_t left_io_block_size;
	error = elu_get_path_preferred_io_block_size(left_list_directory_data.directory_length, left_list_directory_data.directory, &left_io_block_size);
	if (error)
		left_io_block_size = page_size;
	size_t right_io_block_size;
	error = elu_get_path_preferred_io_block_size(right_list_directory_data.directory_length, right_list_directory_data.directory, &right_io_block_size);
	if (error)
		right_io_block_size = page_size;

	const size_t file_buffer_base_size = 0x1000000;
	size_t absolute_name_buffer_length = (left_list_directory_data.directory_length < right_list_directory_data.directory_length ? right_list_directory_data.directory_length : left_list_directory_data.directory_length) + 1 + longest_name_length + 1;
	size_t left_file_buffer_base_size = (((file_buffer_base_size + (left_io_block_size - 1)) / left_io_block_size) * left_io_block_size);
	size_t right_file_buffer_base_size = (((file_buffer_base_size + (right_io_block_size - 1)) / right_io_block_size) * right_io_block_size);
	size_t file_buffer_size = (left_file_buffer_base_size < right_file_buffer_base_size) ? right_file_buffer_base_size : left_file_buffer_base_size;
	void* file_data_tmp_buffer = (void*)VirtualAlloc(0, ((((size_t)4 * file_buffer_size) + absolute_name_buffer_length) + (page_size - 1)) & ~(page_size - 1), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!file_data_tmp_buffer)
	{
		error = ENOMEM;
		elu_write_std_io(33, "Error: Memory allocation failed.\n");
		VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
		VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
		return error;
	}
	void* left_file_load_buffer = file_data_tmp_buffer;
	void* left_file_data_buffer = (void*)((uintptr_t)left_file_load_buffer + ((size_t)1 * file_buffer_size));
	void* right_file_load_buffer = (void*)((uintptr_t)left_file_load_buffer + ((size_t)2 * file_buffer_size));
	void* right_file_data_buffer = (void*)((uintptr_t)left_file_load_buffer + ((size_t)3 * file_buffer_size));
	char* absolute_name_buffer = (char*)((uintptr_t)left_file_load_buffer + ((size_t)4 * file_buffer_size));

#ifdef DIRECTORY_DELTA_DEBUG_TIMERS
	SYSTEMTIME debug_system_time;
	char debug_time_buffer[9];// "HH:MM:SS\n"
	GetSystemTime(&debug_system_time);
	elu_write_std_io(26, "Starting file comparisons ");
	debug_time_buffer[0] = '0' + (char)((debug_system_time.wHour / 10) % 10);
	debug_time_buffer[1] = '0' + (char)(debug_system_time.wHour % 10);
	debug_time_buffer[2] = ':';
	debug_time_buffer[3] = '0' + (char)((debug_system_time.wMinute / 10) % 10);
	debug_time_buffer[4] = '0' + (char)(debug_system_time.wMinute % 10);
	debug_time_buffer[5] = ':';
	debug_time_buffer[6] = '0' + (char)((debug_system_time.wSecond / 10) % 10);
	debug_time_buffer[7] = '0' + (char)(debug_system_time.wSecond % 10);
	debug_time_buffer[8] = '\n';
	elu_write_std_io(9, debug_time_buffer);
#endif

	size_t next_file_size = (size_t)~0;
	elu_handle_t next_file_handle_pair[2]; // Left + right
	size_t next_asynchronous_io_request_size;
	int next_asynchronous_io_flags;
	for (size_t c = 0, i = 0; c != match_count; ++i)
		if (left_list_directory_data.table[i].flags & LIST_SHARED_PATH_FLAG)
		{
			if (!(left_list_directory_data.table[i].flags & LIST_FILE_PATH_FLAG))
			{
				size_t left_file_size;
				size_t right_file_size;
				elu_handle_t file_handle_pair[2]; // Left + right

				if (next_file_size == (size_t)~0)
				{
					uint64_t file_size_64;

					memcpy(absolute_name_buffer, left_list_directory_data.directory, left_list_directory_data.directory_length);
					*(absolute_name_buffer + left_list_directory_data.directory_length) = '\\';
					memcpy(absolute_name_buffer + left_list_directory_data.directory_length + 1, left_list_directory_data.table[i].path, left_list_directory_data.table[i].length);
					*(absolute_name_buffer + left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length) = 0;
					error = elu_open_file(left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer, ELU_READ_PERMISION | ELU_SEQUENTIAL_ACCESS, file_handle_pair + LEFT_INDEX);
					if (error)
					{
						elu_write_std_io(14, "Opening file \"");
						elu_write_std_io(left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer);
						elu_write_std_io(20, "\" failed with error ");
						write_error_to_std_output(error);
						elu_write_std_io(2, ".\n");

						VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
						VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
						VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
						return error;
					}
					error = elu_get_file_size(file_handle_pair[LEFT_INDEX], &file_size_64);
					if (error)
					{
						elu_write_std_io(15, "Querying file \"");
						elu_write_std_io(left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer);
						elu_write_std_io(25, "\" size failed with error ");
						write_error_to_std_output(error);
						elu_write_std_io(2, ".\n");

						elu_close_file(file_handle_pair[LEFT_INDEX]);
						VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
						VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
						VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
						return error;
					}
#ifdef _WIN64
					left_file_size = (size_t)file_size_64;
#else
#error
#endif
					memcpy(absolute_name_buffer, right_list_directory_data.directory, right_list_directory_data.directory_length);
					*(absolute_name_buffer + right_list_directory_data.directory_length) = '\\';
					memcpy(absolute_name_buffer + right_list_directory_data.directory_length + 1, left_list_directory_data.table[i].path, left_list_directory_data.table[i].length);
					*(absolute_name_buffer + right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length) = 0;
					error = elu_open_file(right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer, ELU_READ_PERMISION | ELU_SEQUENTIAL_ACCESS, file_handle_pair + RIGHT_INDEX);
					if (error)
					{
						elu_write_std_io(14, "Opening file \"");
						elu_write_std_io(right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer);
						elu_write_std_io(20, "\" failed with error ");
						write_error_to_std_output(error);
						elu_write_std_io(2, ".\n");

						elu_close_file(file_handle_pair[LEFT_INDEX]);
						VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
						VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
						VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
						return error;
					}
					error = elu_get_file_size(file_handle_pair[RIGHT_INDEX], &file_size_64);
					if (error)
					{
						elu_write_std_io(15, "Querying file \"");
						elu_write_std_io(right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer);
						elu_write_std_io(25, "\" size failed with error ");
						write_error_to_std_output(error);
						elu_write_std_io(2, ".\n");

						elu_close_file(file_handle_pair[RIGHT_INDEX]);
						elu_close_file(file_handle_pair[LEFT_INDEX]);
						VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
						VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
						VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
						return error;
					}
#ifdef _WIN64
					right_file_size = (size_t)file_size_64;
#else
#error
#endif
					next_asynchronous_io_request_size = 0;
					next_asynchronous_io_flags = 0;
				}
				else
				{
					left_file_size = next_file_size;
					right_file_size = next_file_size;
					file_handle_pair[LEFT_INDEX] = next_file_handle_pair[LEFT_INDEX];
					file_handle_pair[RIGHT_INDEX] = next_file_handle_pair[RIGHT_INDEX];

					next_file_size = (size_t)~0;
				}

				int file_content_is_equal = left_file_size == right_file_size;
				if (file_content_is_equal)
				{
					elu_io_result_t io_result_table[2];
					size_t asynchronous_io_request_size = next_asynchronous_io_request_size;
					int asynchronous_io_flags = next_asynchronous_io_flags;
					for (size_t file_read = 0, file_processed = 0; file_processed != left_file_size;)
					{
						if (asynchronous_io_flags)
						{
							for (size_t left_io_complete = 0, right_io_complete = 0; left_io_complete != asynchronous_io_request_size || right_io_complete != asynchronous_io_request_size;)
							{
								int asynchronous_io_count = ((asynchronous_io_flags >> 0) & 0x1) + ((asynchronous_io_flags >> 1) & 0x1);
								int wait_pair_index = ((asynchronous_io_count == 2) || (asynchronous_io_flags & 0x1)) ? 0 : 1;
								size_t io_completion_count;
								error = elu_wait(ELU_WAIT_FOR_NEXT_IO, (size_t)asynchronous_io_count, file_handle_pair + wait_pair_index, &io_completion_count, io_result_table);
								if (!error)
								{
									int left_result_index = -1;
									int right_result_index = -1;
									for (int result_index = 0; result_index != (int)io_completion_count; ++result_index)
									{
										if (io_result_table[result_index].handle == file_handle_pair[LEFT_INDEX])
										{
											asynchronous_io_flags &= ~0x1;
											left_result_index = result_index;
										}
										else if (io_result_table[result_index].handle == file_handle_pair[RIGHT_INDEX])
										{
											asynchronous_io_flags &= ~0x2;
											right_result_index = result_index;
										}
										else
										{
											elu_write_std_io(42, "Asynchronous IO control failed with error ");
											write_error_to_std_output(error);
											elu_write_std_io(2, ".\n");

											// IO data corrupted can not cancel IO.
											error = EIO;
											elu_close_file(file_handle_pair[RIGHT_INDEX]);
											elu_close_file(file_handle_pair[LEFT_INDEX]);
											VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
											VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
											VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
											return error;
										}
									}
									
									if (left_result_index != -1)
									{
#ifdef _DEBUG
										assert((io_result_table[left_result_index].io_type == ELU_IO_TYPE_DATA_TRANSFER));
#endif // _DEBUG
										if (io_result_table[left_result_index].result_error)
										{
											memcpy(absolute_name_buffer, left_list_directory_data.directory, left_list_directory_data.directory_length);
											*(absolute_name_buffer + left_list_directory_data.directory_length) = '\\';
											memcpy(absolute_name_buffer + left_list_directory_data.directory_length + 1, left_list_directory_data.table[i].path, left_list_directory_data.table[i].length);
											*(absolute_name_buffer + left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length) = 0;
											elu_write_std_io(14, "Reading file \"");
											elu_write_std_io(left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer);
											elu_write_std_io(20, "\" failed with error ");
											write_error_to_std_output(error);
											elu_write_std_io(2, ".\n");

											error = io_result_table[left_result_index].result_error;
											if (asynchronous_io_flags & 0x2)
											{
												elu_cancel_io(file_handle_pair[RIGHT_INDEX]);
												elu_wait(ELU_WAIT_FOR_NEXT_IO, 1, file_handle_pair + RIGHT_INDEX, &io_completion_count, io_result_table);
												asynchronous_io_flags &= ~0x2;
											}
											elu_close_file(file_handle_pair[RIGHT_INDEX]);
											elu_close_file(file_handle_pair[LEFT_INDEX]);
											VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
											VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
											VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
											return error;
										}
										
										left_io_complete += io_result_table[left_result_index].data_transfer.size;
										if (left_io_complete != asynchronous_io_request_size)
										{
											error = elu_read_file(file_handle_pair[LEFT_INDEX], (uint64_t)(file_read + left_io_complete), asynchronous_io_request_size - left_io_complete, (void*)((uintptr_t)left_file_load_buffer + left_io_complete));
											if (error)
											{
												memcpy(absolute_name_buffer, left_list_directory_data.directory, left_list_directory_data.directory_length);
												*(absolute_name_buffer + left_list_directory_data.directory_length) = '\\';
												memcpy(absolute_name_buffer + left_list_directory_data.directory_length + 1, left_list_directory_data.table[i].path, left_list_directory_data.table[i].length);
												*(absolute_name_buffer + left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length) = 0;
												elu_write_std_io(14, "Reading file \"");
												elu_write_std_io(left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer);
												elu_write_std_io(20, "\" failed with error ");
												write_error_to_std_output(error);
												elu_write_std_io(2, ".\n");

												if (asynchronous_io_flags & 0x2)
												{
													elu_cancel_io(file_handle_pair[RIGHT_INDEX]);
													elu_wait(ELU_WAIT_FOR_NEXT_IO, 1, file_handle_pair + RIGHT_INDEX, &io_completion_count, io_result_table);
													asynchronous_io_flags &= ~0x2;
												}
												elu_close_file(file_handle_pair[RIGHT_INDEX]);
												elu_close_file(file_handle_pair[LEFT_INDEX]);
												VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
												VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
												VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
												return error;
											}
											asynchronous_io_flags |= 0x1;
										}
									}

									if (right_result_index != -1)
									{
#ifdef _DEBUG
										assert((io_result_table[right_result_index].io_type == ELU_IO_TYPE_DATA_TRANSFER));
#endif // _DEBUG
										if (io_result_table[right_result_index].result_error)
										{
											memcpy(absolute_name_buffer, right_list_directory_data.directory, right_list_directory_data.directory_length);
											*(absolute_name_buffer + right_list_directory_data.directory_length) = '\\';
											memcpy(absolute_name_buffer + right_list_directory_data.directory_length + 1, left_list_directory_data.table[i].path, left_list_directory_data.table[i].length);
											*(absolute_name_buffer + right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length) = 0;
											elu_write_std_io(14, "Reading file \"");
											elu_write_std_io(right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer);
											elu_write_std_io(20, "\" failed with error ");
											write_error_to_std_output(error);
											elu_write_std_io(2, ".\n");

											error = io_result_table[right_result_index].result_error;
											if (asynchronous_io_flags & 0x1)
											{
												elu_cancel_io(file_handle_pair[LEFT_INDEX]);
												elu_wait(ELU_WAIT_FOR_NEXT_IO, 1, file_handle_pair + LEFT_INDEX, &io_completion_count, io_result_table);
												asynchronous_io_flags &= ~0x1;
											}
											elu_close_file(file_handle_pair[RIGHT_INDEX]);
											elu_close_file(file_handle_pair[LEFT_INDEX]);
											VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
											VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
											VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
											return error;
										}

										right_io_complete += io_result_table[right_result_index].data_transfer.size;
										if (right_io_complete != asynchronous_io_request_size)
										{
											error = elu_read_file(file_handle_pair[RIGHT_INDEX], (uint64_t)(file_read + right_io_complete), asynchronous_io_request_size - right_io_complete, (void*)((uintptr_t)right_file_load_buffer + right_io_complete));
											if (error)
											{
												memcpy(absolute_name_buffer, right_list_directory_data.directory, right_list_directory_data.directory_length);
												*(absolute_name_buffer + right_list_directory_data.directory_length) = '\\';
												memcpy(absolute_name_buffer + right_list_directory_data.directory_length + 1, left_list_directory_data.table[i].path, left_list_directory_data.table[i].length);
												*(absolute_name_buffer + right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length) = 0;
												elu_write_std_io(14, "Reading file \"");
												elu_write_std_io(right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer);
												elu_write_std_io(20, "\" failed with error ");
												write_error_to_std_output(error);
												elu_write_std_io(2, ".\n");

												if (asynchronous_io_flags & 0x1)
												{
													elu_cancel_io(file_handle_pair[LEFT_INDEX]);
													elu_wait(ELU_WAIT_FOR_NEXT_IO, 1, file_handle_pair + LEFT_INDEX, &io_completion_count, io_result_table);
													asynchronous_io_flags &= ~0x1;
												}
												elu_close_file(file_handle_pair[RIGHT_INDEX]);
												elu_close_file(file_handle_pair[LEFT_INDEX]);
												VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
												VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
												VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
												return error;
											}
											asynchronous_io_flags |= 0x2;
										}
									}
								}
								else
								{
									elu_write_std_io(42, "Asynchronous IO control failed with error ");
									write_error_to_std_output(error);
									elu_write_std_io(2, ".\n");

									// Waiting for IO has failed.
									error = EIO;
									elu_close_file(file_handle_pair[RIGHT_INDEX]);
									elu_close_file(file_handle_pair[LEFT_INDEX]);
									VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
									VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
									VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
									return error;
								}
							}
							file_read += asynchronous_io_request_size;
							void* left_file_buffer_swap = left_file_data_buffer;
							left_file_data_buffer = left_file_load_buffer;
							left_file_load_buffer = left_file_buffer_swap;
							void* right_file_buffer_swap = right_file_data_buffer;
							right_file_data_buffer = right_file_load_buffer;
							right_file_load_buffer = right_file_buffer_swap;
						}

						if (file_content_is_equal)
						{
							asynchronous_io_request_size = (file_buffer_size < (left_file_size - file_read)) ? file_buffer_size : (left_file_size - file_read);
							if (asynchronous_io_request_size > asynchronous_io_request_size_limit)
								asynchronous_io_request_size = asynchronous_io_request_size_limit;
							if (asynchronous_io_request_size)
							{
								error = elu_read_file(file_handle_pair[LEFT_INDEX], (uint64_t)file_read, asynchronous_io_request_size, left_file_load_buffer);
								if (error)
								{
									memcpy(absolute_name_buffer, left_list_directory_data.directory, left_list_directory_data.directory_length);
									*(absolute_name_buffer + left_list_directory_data.directory_length) = '\\';
									memcpy(absolute_name_buffer + left_list_directory_data.directory_length + 1, left_list_directory_data.table[i].path, left_list_directory_data.table[i].length);
									*(absolute_name_buffer + left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length) = 0;
									elu_write_std_io(14, "Reading file \"");
									elu_write_std_io(left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer);
									elu_write_std_io(20, "\" failed with error ");
									write_error_to_std_output(error);
									elu_write_std_io(2, ".\n");

									elu_close_file(file_handle_pair[RIGHT_INDEX]);
									elu_close_file(file_handle_pair[LEFT_INDEX]);
									VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
									VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
									VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
									return error;
								}
								asynchronous_io_flags |= 0x1;

								error = elu_read_file(file_handle_pair[RIGHT_INDEX], (uint64_t)file_read, asynchronous_io_request_size, right_file_load_buffer);
								if (error)
								{
									memcpy(absolute_name_buffer, right_list_directory_data.directory, right_list_directory_data.directory_length);
									*(absolute_name_buffer + right_list_directory_data.directory_length) = '\\';
									memcpy(absolute_name_buffer + right_list_directory_data.directory_length + 1, left_list_directory_data.table[i].path, left_list_directory_data.table[i].length);
									*(absolute_name_buffer + right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length) = 0;
									elu_write_std_io(14, "Reading file \"");
									elu_write_std_io(right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i].length, absolute_name_buffer);
									elu_write_std_io(20, "\" failed with error ");
									write_error_to_std_output(error);
									elu_write_std_io(2, ".\n");

									elu_cancel_io(file_handle_pair[LEFT_INDEX]);
									size_t cancel_io_completion_count;
									elu_wait(ELU_WAIT_FOR_NEXT_IO, 1, file_handle_pair + LEFT_INDEX, &cancel_io_completion_count, io_result_table);
									asynchronous_io_flags &= ~0x1;
									elu_close_file(file_handle_pair[RIGHT_INDEX]);
									elu_close_file(file_handle_pair[LEFT_INDEX]);
									VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
									VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
									VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
									return error;
								}
								asynchronous_io_flags |= 0x2;
							}
							else if ((i + 1) != left_list_directory_data.count && (left_list_directory_data.table[i + 1].flags & LIST_SHARED_PATH_FLAG) && !(left_list_directory_data.table[i + 1].flags & LIST_FILE_PATH_FLAG))
							{
#ifdef _DEBUG
								assert(!asynchronous_io_flags && next_file_size == (size_t)~0);
#endif // _DEBUG

								uint64_t file_size_64;

								memcpy(absolute_name_buffer, left_list_directory_data.directory, left_list_directory_data.directory_length);
								*(absolute_name_buffer + left_list_directory_data.directory_length) = '\\';
								memcpy(absolute_name_buffer + left_list_directory_data.directory_length + 1, left_list_directory_data.table[i + 1].path, left_list_directory_data.table[i + 1].length);
								*(absolute_name_buffer + left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length) = 0;
								error = elu_open_file(left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length, absolute_name_buffer, ELU_READ_PERMISION | ELU_SEQUENTIAL_ACCESS, next_file_handle_pair + LEFT_INDEX);
								if (error)
								{
									elu_write_std_io(14, "Opening file \"");
									elu_write_std_io(left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length, absolute_name_buffer);
									elu_write_std_io(20, "\" failed with error ");
									write_error_to_std_output(error);
									elu_write_std_io(2, ".\n");

									elu_close_file(file_handle_pair[RIGHT_INDEX]);
									elu_close_file(file_handle_pair[LEFT_INDEX]);
									VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
									VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
									VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
									return error;
								}
								error = elu_get_file_size(next_file_handle_pair[LEFT_INDEX], &file_size_64);
								if (error)
								{
									elu_write_std_io(15, "Querying file \"");
									elu_write_std_io(left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length, absolute_name_buffer);
									elu_write_std_io(25, "\" size failed with error ");
									write_error_to_std_output(error);
									elu_write_std_io(2, ".\n");

									elu_close_file(next_file_handle_pair[LEFT_INDEX]);
									elu_close_file(file_handle_pair[RIGHT_INDEX]);
									elu_close_file(file_handle_pair[LEFT_INDEX]);
									VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
									VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
									VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
									return error;
								}

#ifdef _WIN64
								size_t next_left_file_size = (size_t)file_size_64;
#else
#error
#endif
								memcpy(absolute_name_buffer, right_list_directory_data.directory, right_list_directory_data.directory_length);
								*(absolute_name_buffer + right_list_directory_data.directory_length) = '\\';
								memcpy(absolute_name_buffer + right_list_directory_data.directory_length + 1, left_list_directory_data.table[i + 1].path, left_list_directory_data.table[i + 1].length);
								*(absolute_name_buffer + right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length) = 0;
								error = elu_open_file(right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length, absolute_name_buffer, ELU_READ_PERMISION | ELU_SEQUENTIAL_ACCESS, next_file_handle_pair + RIGHT_INDEX);
								if (error)
								{
									elu_write_std_io(14, "Opening file \"");
									elu_write_std_io(right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length, absolute_name_buffer);
									elu_write_std_io(20, "\" failed with error ");
									write_error_to_std_output(error);
									elu_write_std_io(2, ".\n");

									elu_close_file(next_file_handle_pair[LEFT_INDEX]);
									elu_close_file(file_handle_pair[RIGHT_INDEX]);
									elu_close_file(file_handle_pair[LEFT_INDEX]);
									VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
									VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
									VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
									return error;
								}
								error = elu_get_file_size(next_file_handle_pair[RIGHT_INDEX], &file_size_64);
								if (error)
								{
									elu_write_std_io(15, "Querying file \"");
									elu_write_std_io(right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length, absolute_name_buffer);
									elu_write_std_io(25, "\" size failed with error ");
									write_error_to_std_output(error);
									elu_write_std_io(2, ".\n");

									elu_close_file(next_file_handle_pair[RIGHT_INDEX]);
									elu_close_file(next_file_handle_pair[LEFT_INDEX]);
									elu_close_file(file_handle_pair[RIGHT_INDEX]);
									elu_close_file(file_handle_pair[LEFT_INDEX]);
									VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
									VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
									VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
									return error;
								}
#ifdef _WIN64
								size_t next_right_file_size = (size_t)file_size_64;
#else
#error
#endif
								if (next_left_file_size == next_right_file_size)
								{
									next_asynchronous_io_request_size = (file_buffer_size < next_left_file_size) ? file_buffer_size : next_left_file_size;
									if (next_asynchronous_io_request_size > asynchronous_io_request_size_limit)
										next_asynchronous_io_request_size = asynchronous_io_request_size_limit;
									if (next_asynchronous_io_request_size)
									{
										error = elu_read_file(next_file_handle_pair[LEFT_INDEX], 0, next_asynchronous_io_request_size, left_file_load_buffer);
										if (error)
										{
											memcpy(absolute_name_buffer, left_list_directory_data.directory, left_list_directory_data.directory_length);
											*(absolute_name_buffer + left_list_directory_data.directory_length) = '\\';
											memcpy(absolute_name_buffer + left_list_directory_data.directory_length + 1, left_list_directory_data.table[i + 1].path, left_list_directory_data.table[i + 1].length);
											*(absolute_name_buffer + left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length) = 0;
											elu_write_std_io(14, "Reading file \"");
											elu_write_std_io(left_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length, absolute_name_buffer);
											elu_write_std_io(20, "\" failed with error ");
											write_error_to_std_output(error);
											elu_write_std_io(2, ".\n");

											elu_close_file(next_file_handle_pair[RIGHT_INDEX]);
											elu_close_file(next_file_handle_pair[LEFT_INDEX]);
											elu_close_file(file_handle_pair[RIGHT_INDEX]);
											elu_close_file(file_handle_pair[LEFT_INDEX]);
											VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
											VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
											VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
											return error;
										}

										error = elu_read_file(next_file_handle_pair[RIGHT_INDEX], 0, next_asynchronous_io_request_size, right_file_load_buffer);
										if (error)
										{
											memcpy(absolute_name_buffer, right_list_directory_data.directory, right_list_directory_data.directory_length);
											*(absolute_name_buffer + right_list_directory_data.directory_length) = '\\';
											memcpy(absolute_name_buffer + right_list_directory_data.directory_length + 1, left_list_directory_data.table[i + 1].path, left_list_directory_data.table[i + 1].length);
											*(absolute_name_buffer + right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length) = 0;
											elu_write_std_io(14, "Reading file \"");
											elu_write_std_io(right_list_directory_data.directory_length + 1 + left_list_directory_data.table[i + 1].length, absolute_name_buffer);
											elu_write_std_io(20, "\" failed with error ");
											write_error_to_std_output(error);
											elu_write_std_io(2, ".\n");

											elu_cancel_io(next_file_handle_pair[LEFT_INDEX]);
											size_t cancel_io_completion_count;
											elu_wait(ELU_WAIT_FOR_NEXT_IO, 1, next_file_handle_pair + LEFT_INDEX, &cancel_io_completion_count, io_result_table);

											elu_close_file(next_file_handle_pair[RIGHT_INDEX]);
											elu_close_file(next_file_handle_pair[LEFT_INDEX]);
											elu_close_file(file_handle_pair[RIGHT_INDEX]);
											elu_close_file(file_handle_pair[LEFT_INDEX]);
											VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);
											VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
											VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
											return error;
										}

										next_asynchronous_io_flags = 0x3;
									}
									else
									{
										next_asynchronous_io_flags = 0;
									}
									next_file_size = next_left_file_size;
								}
								else
								{
									elu_close_file(next_file_handle_pair[RIGHT_INDEX]);
									elu_close_file(next_file_handle_pair[LEFT_INDEX]);
								}
							}

							size_t bytes_to_process = file_read - file_processed;
							if (bytes_to_process)
							{
								file_content_is_equal = !memcmp(left_file_data_buffer, right_file_data_buffer, bytes_to_process);
								file_processed = file_read;
							}
						}
						else
							break;
					}
				}

				elu_close_file(file_handle_pair[RIGHT_INDEX]);
				elu_close_file(file_handle_pair[LEFT_INDEX]);

				if (file_content_is_equal)
				{
					left_list_directory_data.table[i].flags |= LIST_CONTENT_EQUAL_FLAG;
					right_list_directory_data.table[left_list_directory_data.table[i].path_pair_index].flags |= LIST_CONTENT_EQUAL_FLAG;
					++equal_file_count;
				}
			}
			else
			{
				left_list_directory_data.table[i].flags |= LIST_CONTENT_EQUAL_FLAG;
				right_list_directory_data.table[left_list_directory_data.table[i].path_pair_index].flags |= LIST_CONTENT_EQUAL_FLAG;
				++equal_file_count;
			}
			++c;
		}

	VirtualFree(file_data_tmp_buffer, 0, MEM_RELEASE);

	write_number_to_std_output(statistical_byte_read_count);
	elu_write_std_io(40, " bytes read.\nComparing files completed. ");
	write_number_to_std_output(left_list_directory_data.count);
	elu_write_std_io(13, " entries on \"");
	elu_write_std_io(left_list_directory_data.directory_length, left_list_directory_data.directory);
	elu_write_std_io(6, "\" and ");
	write_number_to_std_output(right_list_directory_data.count);
	elu_write_std_io(13, " entries on \"");
	elu_write_std_io(right_list_directory_data.directory_length, right_list_directory_data.directory);
	elu_write_std_io(3, "\".\n");
	write_number_to_std_output(equal_file_count);
	elu_write_std_io(25, " entry contents matched.\n");
	write_number_to_std_output(match_count - equal_file_count);
	elu_write_std_io(28, " entry contents differ (~).\n");
	write_number_to_std_output(left_delta_count);
	elu_write_std_io(25, " additional entries (+).\n");
	write_number_to_std_output(right_delta_count);
	elu_write_std_io(22, " missing entries (-).\n");

	if (extended_report)
	{
		for (size_t c = 0, i = 0; c != equal_file_count; ++i)
			if (left_list_directory_data.table[i].flags & LIST_CONTENT_EQUAL_FLAG)
			{
				elu_write_std_io(3, ". \"");
				elu_write_std_io(left_list_directory_data.table[i].length, left_list_directory_data.table[i].path);
				elu_write_std_io(2, "\"\n");
				++c;
			}
	}

	for (size_t n = match_count - equal_file_count, c = 0, i = 0; c != n; ++i)
		if ((left_list_directory_data.table[i].flags & LIST_SHARED_PATH_FLAG) && !(left_list_directory_data.table[i].flags & LIST_CONTENT_EQUAL_FLAG))
		{
			elu_write_std_io(3, "~ \"");
			elu_write_std_io(left_list_directory_data.table[i].length, left_list_directory_data.table[i].path);
			elu_write_std_io(2, "\"\n");
			++c;
		}

	for (size_t c = 0, i = 0; c != left_delta_count; ++i)
		if (!(left_list_directory_data.table[i].flags & LIST_SHARED_PATH_FLAG))
		{
			elu_write_std_io(3, "+ \"");
			elu_write_std_io(left_list_directory_data.table[i].length, left_list_directory_data.table[i].path);
			elu_write_std_io(2, "\"\n");
			++c;
		}

	for (size_t c = 0, i = 0; c != right_delta_count; ++i)
		if (!(right_list_directory_data.table[i].flags & LIST_SHARED_PATH_FLAG))
		{
			elu_write_std_io(3, "- \"");
			elu_write_std_io(right_list_directory_data.table[i].length, right_list_directory_data.table[i].path);
			elu_write_std_io(2, "\"\n");
			++c;
		}

	VirtualFree(left_list_directory_data.table, 0, MEM_RELEASE);
	VirtualFree(right_list_directory_data.table, 0, MEM_RELEASE);
	return 0;
}

void main()
{
#ifdef DIRECTORY_DELTA_DEBUG_TIMERS
	SYSTEMTIME debug_system_time;
	char debug_time_buffer[9];// "HH:MM:SS\n"
#endif // DIRECTORY_DELTA_DEBUG_TIMERS

	elu_write_std_io(64, "Directory Delta Tool (c) Archiver Sakari N. No rights reserved.\n");

	elu_allocator_context_t allocator_context = {
		.context = 0,
		.allocator_procedure = allocator_callback,
		.deallocator_procedure = deallocator_callback };

	size_t argument_count;
	size_t* argument_length_table;
	char** argument_table;
	int error = elu_get_process_arguments(&argument_count, &argument_length_table, &argument_table);
	if (error)
	{
		elu_write_std_io(6, "Error ");
		write_error_to_std_output(error);
		elu_write_std_io(42, " occurred when reading process arguments.\n");
		ExitProcess(EXIT_FAILURE);
	}

	if (argument_count < 3)
	{
		elu_write_std_io(81, "No directories specified. Two directory arguments are required for this program.\n");
		VirtualFree(argument_table, 0, MEM_RELEASE);
		ExitProcess(EXIT_FAILURE);
	}

	size_t left_directory_length;
	char* left_directory;
	error = elu_allocate_and_make_path(&allocator_context, 0, 0, argument_length_table[1], argument_table[1], &left_directory, &left_directory_length);
	if (error)
	{
		elu_write_std_io(6, "Error ");
		write_error_to_std_output(error);
		elu_write_std_io(49, " occurred when creating absolute file path from \"");
		elu_write_std_io(argument_length_table[1], argument_table[1]);
		elu_write_std_io(22, "\" for left parameter.\n");

		VirtualFree(argument_table, 0, MEM_RELEASE);
		ExitProcess(EXIT_FAILURE);
	}

	size_t right_directory_length;
	char* right_directory;
	error = elu_allocate_and_make_path(&allocator_context, 0, 0, argument_length_table[2], argument_table[2], &right_directory, &right_directory_length);
	if (error)
	{
		elu_write_std_io(6, "Error ");
		write_error_to_std_output(error);
		elu_write_std_io(49, " occurred when creating absolute file path from \"");
		elu_write_std_io(argument_length_table[2], argument_table[2]);
		elu_write_std_io(22, "\" for right parameter.\n");

		VirtualFree(left_directory, 0, MEM_RELEASE);
		VirtualFree(argument_table, 0, MEM_RELEASE);
		ExitProcess(EXIT_FAILURE);
	}

	int extended_report = (argument_count > 3);
	if (extended_report)
	{
		extended_report = 0;
		for (size_t i = 3; !extended_report && i != argument_count; ++i)
			if (argument_length_table[i] == 17 && !memcmp(argument_table[i], "--extended_report", 17))
				extended_report = 1;
	}

#ifdef DIRECTORY_DELTA_DEBUG_TIMERS
	elu_write_std_io(20, "Starting comparison ");
	GetSystemTime(&debug_system_time);
	debug_time_buffer[0] = '0' + (char)((debug_system_time.wHour / 10) % 10);
	debug_time_buffer[1] = '0' + (char)(debug_system_time.wHour % 10);
	debug_time_buffer[2] = ':';
	debug_time_buffer[3] = '0' + (char)((debug_system_time.wMinute / 10) % 10);
	debug_time_buffer[4] = '0' + (char)(debug_system_time.wMinute % 10);
	debug_time_buffer[5] = ':';
	debug_time_buffer[6] = '0' + (char)((debug_system_time.wSecond / 10) % 10);
	debug_time_buffer[7] = '0' + (char)(debug_system_time.wSecond % 10);
	debug_time_buffer[8] = '\n';
	elu_write_std_io(9, debug_time_buffer);
#endif // DIRECTORY_DELTA_DEBUG_TIMERS

	error = directory_delta(extended_report, &allocator_context, left_directory_length, left_directory, right_directory_length, right_directory);
	if (!error)
	{
		elu_write_std_io(48, "Directory delta program completed successfully.\n");
	}
	else
	{
		elu_write_std_io(42, "Directory delta program failed with error ");
		write_error_to_std_output(error);
		elu_write_std_io(2, ".\n");
	}

#ifdef DIRECTORY_DELTA_DEBUG_TIMERS
	elu_write_std_io(17, "Comparison ended ");
	GetSystemTime(&debug_system_time);
	debug_time_buffer[0] = '0' + (char)((debug_system_time.wHour / 10) % 10);
	debug_time_buffer[1] = '0' + (char)(debug_system_time.wHour % 10);
	debug_time_buffer[2] = ':';
	debug_time_buffer[3] = '0' + (char)((debug_system_time.wMinute / 10) % 10);
	debug_time_buffer[4] = '0' + (char)(debug_system_time.wMinute % 10);
	debug_time_buffer[5] = ':';
	debug_time_buffer[6] = '0' + (char)((debug_system_time.wSecond / 10) % 10);
	debug_time_buffer[7] = '0' + (char)(debug_system_time.wSecond % 10);
	debug_time_buffer[8] = '\n';
	elu_write_std_io(9, debug_time_buffer);
#endif // DIRECTORY_DELTA_DEBUG_TIMERS

	VirtualFree(right_directory, 0, MEM_RELEASE);
	VirtualFree(left_directory, 0, MEM_RELEASE);
	VirtualFree(argument_table, 0, MEM_RELEASE);

	ExitProcess(error ? EXIT_FAILURE : EXIT_SUCCESS);
}

#ifdef _MSC_VER
#pragma warning( pop )
#endif // _MSC_VER

#ifdef __cplusplus
}
#endif // __cplusplus
