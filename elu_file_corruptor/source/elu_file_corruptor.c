/*
	File Corruptor Tool authored by archiver Sakari N.
	Description

		Simple tool for corrupting files by flipping random bits.
		The tool is used by executing it in the following manner
		"elu_file_corruptor.exe <bit corruption ration> <input file> <output file>".

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

#include <stddef.h>
#include <stdint.h>
#include "elu_error.h"
#include "elu_process.h"
#include "elu_memory.h"
#include "elu_file_api.h"
#include "elu_std_io.h"
#include "elu_time.h"

#define STATIC_STRING(x) (sizeof(x) - 1), (x)

static const uint64_t pcg32_multiplier = 6364136223846793005u; // Or something seed - dependent
static const uint64_t pcg32_increment = 1442695040888963407u; // Or an arbitrary odd constant

static uint32_t pcg32(uint64_t* state);

static void pcg32_init(uint64_t* state, uint64_t seed);

static void* allocator_callback(void* context, size_t size);

static void deallocator_callback(void* context, size_t size, void* allocation);

static int decode_decimal_u32(size_t text_length, const char* text, uint32_t* integer_address);

static int write_number_to_std_output(size_t number);

void elu_file_corruptor()
{
	elu_write_std_io(STATIC_STRING("File Corruptor Tool (c) Archiver Sakari N. No rights reserved.\n"));

	elu_allocator_context_t allocator_context = {
		.context = 0,
		.allocator_procedure = allocator_callback,
		.deallocator_procedure = deallocator_callback };

	size_t argument_table_size;
	size_t argument_count;
	size_t* argument_length_table;
	char** argument_table;
	int error = elu_get_process_arguments(&argument_count, &argument_length_table, &argument_table, &argument_table_size);
	if (error)
	{
		elu_write_std_io(STATIC_STRING("Error: Failed to query process arguments.\n"));
		elu_exit_process(error);
	}

	if (argument_count < 4)
	{
		elu_write_std_io(STATIC_STRING("Error: Invalid process arguments.\nThe program must be executed in the following manner \"elu_file_corruptor.exe <bit corruption ration> <input file> <output file>\".\n"));
		elu_free_memory(argument_table_size, argument_table);
		elu_exit_process(error);
	}

	uint32_t corruption_ration;
	error = decode_decimal_u32(argument_length_table[1], argument_table[1], &corruption_ration);
	if (error)
	{
		elu_write_std_io(STATIC_STRING("Error: Invalid corruption ration argument. This argument must be nonnegative integer with value less than 2^32.\n"));
		elu_free_memory(argument_table_size, argument_table);
		elu_exit_process(error);
	}

	size_t input_file_path_length;
	char* input_file_path;
	error = elu_allocate_and_make_path(&allocator_context, 0, 0, argument_length_table[2], argument_table[2], &input_file_path, &input_file_path_length);
	if (error)
	{
		elu_write_std_io(STATIC_STRING("Error: Failed to process input file path \""));
		elu_write_std_io(argument_length_table[2], argument_table[2]);
		elu_write_std_io(STATIC_STRING("\".\n"));
		elu_free_memory(argument_table_size, argument_table);
		elu_exit_process(error);
	}

	size_t output_file_path_length;
	char* output_file_path;
	error = elu_allocate_and_make_path(&allocator_context, 0, 0, argument_length_table[3], argument_table[3], &output_file_path, &output_file_path_length);
	if (error)
	{
		elu_write_std_io(STATIC_STRING("Error: Failed to process output file path \""));
		elu_write_std_io(argument_length_table[3], argument_table[3]);
		elu_write_std_io(STATIC_STRING("\".\n"));
		elu_free_memory(input_file_path_length, input_file_path);
		elu_free_memory(argument_table_size, argument_table);
		elu_exit_process(error);
	}

	elu_write_std_io(STATIC_STRING("Creating corrupted version of file \""));
	elu_write_std_io(input_file_path_length, input_file_path);
	elu_write_std_io(STATIC_STRING("\" and storing it to file \""));
	elu_write_std_io(output_file_path_length, output_file_path);
	elu_write_std_io(STATIC_STRING("\". Bit corruption ration is 1/"));
	write_number_to_std_output((size_t)corruption_ration);
	elu_write_std_io(STATIC_STRING(".\n"));

	elu_write_std_io(STATIC_STRING("Loading input file...\n"));
	size_t file_size;
	void* file_data;
	error = elu_allocate_and_load_file(input_file_path_length, input_file_path, &allocator_context, &file_size, &file_data);
	if (error)
	{
		elu_write_std_io(STATIC_STRING("Error: Failed to load input file.\n"));
		elu_free_memory(output_file_path_length, output_file_path);
		elu_free_memory(input_file_path_length, input_file_path);
		elu_free_memory(argument_table_size, argument_table);
		elu_exit_process(0);
	}

	elu_write_std_io(STATIC_STRING("Corrupting file data...\n"));
	uint64_t pcg32_state;
	pcg32_init(&pcg32_state, elu_get_time());
	for (void* iterator = file_data, * end = (void*)((uintptr_t)file_data + file_size); iterator != end; iterator = (void*)((uintptr_t)iterator + 1))
	{
		uint8_t byte_corruption_mask = 0;
		for (int i = 0; i != 8; ++i)
		{
			// lol this is not properly calculated, but it is good enough just like modeling humans as 100 kg spheres.
			byte_corruption_mask |= (!(pcg32(&pcg32_state) % corruption_ration) ? 1 : 0) << i;
		}
		*(uint8_t*)iterator = (byte_corruption_mask & (uint8_t)pcg32(&pcg32_state)) | (~byte_corruption_mask & *(uint8_t*)iterator);
	}

	elu_write_std_io(STATIC_STRING("Storing corrupted file data...\n"));
	error = elu_store_file(output_file_path_length, output_file_path, file_size, file_data);
	elu_free_memory(file_size, file_data);
	if (error)
	{
		elu_write_std_io(STATIC_STRING("Error: Failed to store output file.\n"));
		elu_free_memory(output_file_path_length, output_file_path);
		elu_free_memory(input_file_path_length, input_file_path);
		elu_free_memory(argument_table_size, argument_table);
		elu_exit_process(0);
	}

	elu_write_std_io(STATIC_STRING("File corrupted and stored successfully.\n"));
	elu_free_memory(output_file_path_length, output_file_path);
	elu_free_memory(input_file_path_length, input_file_path);
	elu_free_memory(argument_table_size, argument_table);
	elu_exit_process(0);
}

static uint32_t pcg32(uint64_t* state)
{
	uint64_t x = *state;
	uint32_t count = (uint32_t)(x >> 59);
	*state = x * pcg32_multiplier + pcg32_increment;
	x ^= x >> 18;
	uint32_t tmp = (uint32_t)(x >> 27);
	return tmp >> count | tmp << ((0 - count) & 31);
}

static void pcg32_init(uint64_t* state, uint64_t seed)
{
	*state = seed + pcg32_increment;
	pcg32(state);
}

static void* allocator_callback(void* context, size_t size)
{
	void* memory;
	int error = elu_allocate_memory(size, &memory);
	return !error ? memory : 0;
}

static void deallocator_callback(void* context, size_t size, void* allocation)
{
	elu_free_memory(size, allocation);
}

static int decode_decimal_u32(size_t text_length, const char* text, uint32_t* integer_address)
{
	size_t length = 0;
	uint32_t integer = 0;
	while (length != text_length && text[length] >= '0' && text[length] <= '9')
	{
		uint32_t tmp = integer * (uint32_t)10;
		if (tmp / (uint32_t)10 != integer)
		{
			return ERANGE;
		}
		integer = tmp;
		tmp = integer + (uint32_t)(text[length] - '0');
		if (tmp < integer)
		{
			return ERANGE;
		}
		integer = tmp;
		++length;
	}
	if (!length)
	{
		return EINVAL;
	}
	*integer_address = integer;
	return 0;
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