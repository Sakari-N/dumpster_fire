#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "elu_time.h"
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

uint64_t elu_get_time()
{
	uint64_t file_time;
	GetSystemTimeAsFileTime((FILETIME*)&file_time);
	return (file_time - (uint64_t)116444736000000000) / (uint64_t)10000000;
}

#ifdef __cplusplus
}
#endif // __cplusplus