/*
	File access API authored by archiver Sakari N.

	Description

		General purpose file access API.
		This interface is for generic file system operations such as read, write, create, delete enumerate.

		For usage of this interface setup reasonable stack size since any thread calling this API.
		Something like 128 KiB is probably good.

		The interface uses nice UTF-8 encoding for everything to minimize encoding issues, but
		the Win32 implementation uses native UTF-16 to avoid limitations for other encodings.

		This API was done mainly for experimentation and is still incomplete, but working.

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

#ifndef ELU_FILE_API_H
#define ELU_FILE_API_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#include <Windows.h>
typedef int elu_handle_t;
#else
typedef int elu_handle_t;
#endif // _WIN32

// TODO: lol add descriptions for everything when this thing is finished.

#define ELU_INVALID_HANDLE_VALUE ((elu_handle_t)-1)

#define ELU_READ_PERMISION 0x1
#define ELU_WRITE_PERMISION 0x2
#define ELU_EXECUTE_PERMISION 0x4

#define ELU_CREATE 0x8
#define ELU_TRUNCATE 0x10
#define ELU_CREATE_PATH 0x20

#define ELU_SEQUENTIAL_ACCESS 0x40

#define ELU_WAIT_FOR_NEXT_IO INFINITE

typedef void* (*elu_allocator_callback_t)(void* context, size_t size);
typedef void (*elu_deallocator_callback_t)(void* context, size_t size, void* allocation);

typedef struct elu_allocator_context_t
{
	void* context;
	elu_allocator_callback_t allocator_procedure;
	elu_deallocator_callback_t deallocator_procedure;
} elu_allocator_context_t;

typedef struct elu_file_entry_t
{
	size_t name_length;
	char* name;
} elu_file_entry_t;

#define ELU_IO_TYPE_DATA_TRANSFER 0

#define ELU_OBJECT_TYPE_UNDEFINED 0
#define ELU_OBJECT_TYPE_FILE 1

typedef struct elu_io_result_t
{
	elu_handle_t handle;
	int object_type;
	int io_type;
	int result_error;
	union
	{
		struct
		{
			size_t size;
			void* buffer;
		} data_transfer;
	};
} elu_io_result_t;

int elu_open_file(size_t name_length, const char* name, int permissions_and_flags, elu_handle_t* handle_address);

int elu_close_file(elu_handle_t handle);

int elu_get_path_preferred_io_block_size(size_t name_length, const char* name, size_t* io_size_address);

int elu_get_file_preferred_io_block_size(elu_handle_t handle, size_t* io_size_address);

int elu_get_file_size(elu_handle_t handle, uint64_t* file_size_address);

int elu_truncate_file(elu_handle_t handle, uint64_t file_size);

int elu_flush_file_buffers(elu_handle_t handle);

int elu_read_file(elu_handle_t handle, uint64_t file_offset, size_t io_size, void* buffer);

int elu_write_file(elu_handle_t handle, uint64_t file_offset, size_t io_size, const void* buffer);

int elu_wait(uint32_t timeout_milliseconds, size_t handle_count, elu_handle_t* handle_table, size_t* io_completion_count_address, elu_io_result_t* io_completion_result_table);

int elu_cancel_io(elu_handle_t handle);

int elu_load_file(size_t name_length, const char* name, size_t buffer_size, void* buffer, size_t* file_size_address);

int elu_allocate_and_load_file(size_t name_length, const char* name, elu_allocator_context_t* allocator_context, size_t* file_size_address, void** file_data_address);

int elu_store_file(size_t name_length, const char* name, size_t size, const void* data);

int elu_delete_file(size_t name_length, const char* name);

int elu_delete_directory(size_t name_length, const char* name);

int elu_move_file(size_t old_name_length, const char* old_name, size_t new_name_length, const char* new_name);

int elu_move_directory(size_t old_name_length, const char* old_name, size_t new_name_length, const char* new_name);

int elu_create_directory(size_t name_length, const char* name);

int elu_list_directory(size_t name_length, const char* name, size_t buffer_size, elu_file_entry_t* buffer, size_t* required_buffer_size_address, size_t* directory_count_address, size_t* file_count_address);

int elu_allocate_and_list_directory(size_t name_length, const char* name, elu_allocator_context_t* allocator_context, size_t* entry_table_size_address, elu_file_entry_t** entry_table_address, size_t* directory_count_address, size_t* file_count_address);

int elu_get_executable_file_name(size_t buffer_size, char* buffer, size_t* file_name_length);

int elu_allocate_and_get_executable_file_name(elu_allocator_context_t* allocator_context, char** file_name_address, size_t* file_name_length_address);

int elu_get_program_directory(size_t buffer_size, char* buffer, size_t* directory_name_length_address);

int elu_allocate_and_get_program_directory(elu_allocator_context_t* allocator_context, char** directory_name_address, size_t* directory_name_length_address);

int elu_get_data_directory(size_t buffer_size, size_t sub_directory_name_length, const char* sub_directory_name, char* buffer, size_t* directory_name_length_address);

int elu_allocate_and_get_data_directory(elu_allocator_context_t* allocator_context, size_t sub_directory_name_length, const char* sub_directory_name, char** directory_name_address, size_t* directory_name_length_address);

int elu_make_path(size_t parent_directory_length, const char* parent_directory, size_t sub_directory_length, const char* sub_directory, size_t buffer_size, char* buffer, size_t* directory_name_length_address);

int elu_allocate_and_make_path(elu_allocator_context_t* allocator_context, size_t parent_directory_length, const char* parent_directory, size_t sub_directory_length, const char* sub_directory, char** directory_name_address, size_t* directory_name_length_address);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // ELU_FILE_API_H