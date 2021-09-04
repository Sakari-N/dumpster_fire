#ifndef ELU_MEMORY_H
#define ELU_MEMORY_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stddef.h>

size_t elu_get_memory_page_size();

int elu_allocate_memory(size_t size, void** memory_address);

int elu_free_memory(size_t size, void* memory);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // ELU_MEMORY_H
