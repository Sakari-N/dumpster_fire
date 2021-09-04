/*
	Simple POSIX error code to text convertion API authored by archiver Sakari N.

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

#include "elu_error.h"

#if defined(_WIN32)

#define ELU_INTERNAL_ERROR_OFFSET_TABLE_LENGTH 141
#define ELU_INTERNAL_UNKNOWN_ERROR_DESCRIPTION_OFFSET 0
#define ELU_INTERNAL_UNKNOWN_ERROR_NAME_OFFSET 2492

static const char* elu_internal_error_string_pool =
	"Unknown error\0"
	"No error\0"
	"Operation not permitted\0"
	"No such file or directory\0"
	"No such process\0"
	"Interrupted system call\0"
	"I/O error\0"
	"No such device or address\0"
	"Arg list too long\0"
	"Exec format error\0"
	"Bad file number\0"
	"No child processes\0"
	"Try again\0"
	"Out of memory\0"
	"Permission denied\0"
	"Bad address\0"
	"Block device required\0"
	"Device or resource busy\0"
	"File exists\0"
	"Cross-device link\0"
	"No such device\0"
	"Not a directory\0"
	"Is a directory\0"
	"Invalid argument\0"
	"File table overflow\0"
	"Too many open files\0"
	"Not a typewriter\0"
	"File too large\0"
	"No space left on device\0"
	"Illegal seek\0"
	"Read-only file system\0"
	"Too many links\0"
	"Broken pipe\0"
	"Math argument out of domain of function\0"
	"Math result not representable\0"
	"Resource deadlock would occur\0"
	"File name too long\0"
	"No record locks available\0"
	"Function not implemented\0"
	"Directory not empty\0"
	"Illegal byte sequence\0"
	"Address already in use\0"
	"Cannot assign requested address\0"
	"Address family not supported by protocol\0"
	"Operation already in progress\0"
	"Not a data message\0"
	"Operation canceled\0"
	"Software caused connection abort\0"
	"Connection refused\0"
	"Connection reset by peer\0"
	"Destination address required\0"
	"No route to host\0"
	"Identifier removed\0"
	"Operation now in progress\0"
	"Transport endpoint is already connected\0"
	"Too many symbolic links encountered\0"
	"Message too long\0"
	"Network is down\0"
	"Network dropped connection because of reset\0"
	"Network is unreachable\0"
	"No buffer space available\0"
	"No data available\0"
	"Link has been severed\0"
	"No message of desired type\0"
	"Protocol not available\0"
	"Out of streams resources\0"
	"Device not a stream\0"
	"Transport endpoint is not connected\0"
	"State not recoverable\0"
	"Socket operation on non-socket\0"
	"Operation not supported\0"
	"Operation not supported on transport endpoint\0"
	"Other error\0"
	"Value too large for defined data type\0"
	"Owner died\0"
	"Protocol error\0"
	"Protocol not supported\0"
	"Protocol wrong type for socket\0"
	"Timer expired\0"
	"Connection timed out\0"
	"Text file busy\0"
	"Operation would block\0"
	"\0"
	"\0"
	"EPERM\0"
	"ENOENT\0"
	"ESRCH\0"
	"EINTR\0"
	"EIO\0"
	"ENXIO\0"
	"E2BIG\0"
	"ENOEXEC\0"
	"EBADF\0"
	"ECHILD\0"
	"EAGAIN\0"
	"ENOMEM\0"
	"EACCES\0"
	"EFAULT\0"
	"ENOTBLK\0"
	"EBUSY\0"
	"EEXIST\0"
	"EXDEV\0"
	"ENODEV\0"
	"ENOTDIR\0"
	"EISDIR\0"
	"EINVAL\0"
	"ENFILE\0"
	"EMFILE\0"
	"ENOTTY\0"
	"EFBIG\0"
	"ENOSPC\0"
	"ESPIPE\0"
	"EROFS\0"
	"EMLINK\0"
	"EPIPE\0"
	"EDOM\0"
	"ERANGE\0"
	"EDEADLK\0"
	"ENAMETOOLONG\0"
	"ENOLCK\0"
	"ENOSYS\0"
	"ENOTEMPTY\0"
	"EILSEQ\0"
	"EADDRINUSE\0"
	"EADDRNOTAVAIL\0"
	"EAFNOSUPPORT\0"
	"EALREADY\0"
	"EBADMSG\0"
	"ECANCELED\0"
	"ECONNABORTED\0"
	"ECONNREFUSED\0"
	"ECONNRESET\0"
	"EDESTADDRREQ\0"
	"EHOSTUNREACH\0"
	"EIDRM\0"
	"EINPROGRESS\0"
	"EISCONN\0"
	"ELOOP\0"
	"EMSGSIZE\0"
	"ENETDOWN\0"
	"ENETRESET\0"
	"ENETUNREACH\0"
	"ENOBUFS\0"
	"ENODATA\0"
	"ENOLINK\0"
	"ENOMSG\0"
	"ENOPROTOOPT\0"
	"ENOSR\0"
	"ENOSTR\0"
	"ENOTCONN\0"
	"ENOTRECOVERABLE\0"
	"ENOTSOCK\0"
	"ENOTSUP\0"
	"EOPNOTSUPP\0"
	"EOTHER\0"
	"EOVERFLOW\0"
	"EOWNERDEAD\0"
	"EPROTO\0"
	"EPROTONOSUPPORT\0"
	"EPROTOTYPE\0"
	"ETIME\0"
	"ETIMEDOUT\0"
	"ETXTBSY\0"
	"EWOULDBLOCK";

static const int elu_internal_error_description_offset_table[ELU_INTERNAL_ERROR_OFFSET_TABLE_LENGTH] = {
	14, 23, 47, 73, 89, 113, 123, 149, 167, 185, 201, 220, 230, 244, 262, 274,
	296, 320, 332, 350, 365, 381, 396, 413, 433, 453, 0, 470, 485, 509, 522, 544,
	559, 571, 611, 0, 641, 0, 671, 690, 716, 741, 761, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 783, 806, 838, 879, 909, 928, 947, 980, 999, 1024, 1053, 1070,
	1089, 1115, 1155, 1191, 1208, 1224, 1268, 1291, 1317, 1335, 1357, 1384, 1407, 1432, 1452, 1488,
	1510, 1541, 1565, 1611, 1623, 1661, 1672, 1687, 1710, 1741, 1755, 1776, 1791 };

static const int elu_internal_error_name_offset_table[ELU_INTERNAL_ERROR_OFFSET_TABLE_LENGTH] = {
	1814, 1815, 1821, 1828, 1834, 1840, 1844, 1850, 1856, 1864, 1870, 1877, 1884, 1891, 1898, 1905,
	1913, 1919, 1926, 1932, 1939, 1947, 1954, 1961, 1968, 1975, 2492, 1982, 1988, 1995, 2002, 2008,
	2015, 2021, 2026, 2492, 2033, 2492, 2041, 2054, 2061, 2068, 2078, 2492, 2492, 2492, 2492, 2492,
	2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492,
	2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492,
	2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492, 2492,
	2492, 2492, 2492, 2492, 2085, 2096, 2110, 2123, 2132, 2140, 2150, 2163, 2176, 2187, 2200, 2213,
	2219, 2231, 2239, 2245, 2254, 2263, 2273, 2285, 2293, 2301, 2309, 2316, 2328, 2334, 2341, 2350,
	2366, 2375, 2383, 2394, 2401, 2411, 2422, 2429, 2445, 2456, 2462, 2472, 2480 };

#elif defined(__linux__) || defined(linux) || defined(__linux)

#define ELU_INTERNAL_ERROR_OFFSET_TABLE_LENGTH 134
#define ELU_INTERNAL_UNKNOWN_ERROR_DESCRIPTION_OFFSET 0
#define ELU_INTERNAL_UNKNOWN_ERROR_NAME_OFFSET 4165

static const char* elu_internal_error_string_pool =
	"Unknown error\0"
	"No error\0"
	"Operation not permitted\0"
	"No such file or directory\0"
	"No such process\0"
	"Interrupted system call\0"
	"I/O error\0"
	"No such device or address\0"
	"Arg list too long\0"
	"Exec format error\0"
	"Bad file number\0"
	"No child processes\0"
	"Try again\0"
	"Out of memory\0"
	"Permission denied\0"
	"Bad address\0"
	"Block device required\0"
	"Device or resource busy\0"
	"File exists\0"
	"Cross-device link\0"
	"No such device\0"
	"Not a directory\0"
	"Is a directory\0"
	"Invalid argument\0"
	"File table overflow\0"
	"Too many open files\0"
	"Not a typewriter\0"
	"Text file busy\0"
	"File too large\0"
	"No space left on device\0"
	"Illegal seek\0"
	"Read-only file system\0"
	"Too many links\0"
	"Broken pipe\0"
	"Math argument out of domain of function\0"
	"Math result not representable\0"
	"Resource deadlock would occur\0"
	"File name too long\0"
	"No record locks available\0"
	"Function not implemented\0"
	"Directory not empty\0"
	"Too many symbolic links encountered\0"
	"No message of desired type\0"
	"Identifier removed\0"
	"Channel number out of range\0"
	"Level 2 not synchronized\0"
	"Level 3 halted\0"
	"Level 3 reset\0"
	"Link number out of range\0"
	"Protocol driver not attached\0"
	"No CSI structure available\0"
	"Level 2 halted\0"
	"Invalid exchange\0"
	"Invalid request descriptor\0"
	"Exchange full\0"
	"No anode\0"
	"Invalid request code\0"
	"Invalid slot\0"
	"Bad font file format\0"
	"Device not a stream\0"
	"No data available\0"
	"Timer expired\0"
	"Out of streams resources\0"
	"Machine is not on the network\0"
	"Package not installed\0"
	"Object is remote\0"
	"Link has been severed\0"
	"Advertise error\0"
	"Srmount error\0"
	"Communication error on send\0"
	"Protocol error\0"
	"Multihop attempted\0"
	"RFS specific error\0"
	"Not a data message\0"
	"Value too large for defined data type\0"
	"Name not unique on network\0"
	"File descriptor in bad state\0"
	"Remote address changed\0"
	"Can not access a needed shared library\0"
	"Accessing a corrupted shared library\0"
	"Library section corrupted\0"
	"Attempting to link in too many shared libraries\0"
	"Cannot execute a shared library directly\0"
	"Illegal byte sequence\0"
	"Interrupted system call should be restarted\0"
	"Streams pipe error\0"
	"Too many users\0"
	"Socket operation on non-socket\0"
	"Destination address required\0"
	"Message too long\0"
	"Protocol wrong type for socket\0"
	"Protocol not available\0"
	"Protocol not supported\0"
	"Socket type not supported\0"
	"Operation not supported on transport endpoint\0"
	"Protocol family not supported\0"
	"Address family not supported by protocol\0"
	"Address already in use\0"
	"Cannot assign requested address\0"
	"Network is down\0"
	"Network is unreachable\0"
	"Network dropped connection because of reset\0"
	"Software caused connection abort\0"
	"Connection reset by peer\0"
	"No buffer space available\0"
	"Transport endpoint is already connected\0"
	"Transport endpoint is not connected\0"
	"Cannot send after transport endpoint shutdown\0"
	"Too many references\0"
	"Connection timed out\0"
	"Connection refused\0"
	"Host is down\0"
	"No route to host\0"
	"Operation already in progress\0"
	"Operation now in progress\0"
	"Stale NFS file handle\0"
	"Structure needs cleaning\0"
	"Not a XENIX named type file\0"
	"No XENIX semaphores available\0"
	"Is a named type file\0"
	"Remote I/O error\0"
	"Quota exceeded\0"
	"No medium found\0"
	"Wrong medium type\0"
	"Operation canceled\0"
	"Required key not available\0"
	"Key has expired\0"
	"Key has been revoked\0"
	"Key was rejected by service\0"
	"Owner died\0"
	"State not recoverable\0"
	"Operation not possible due to RF-kill\0"
	"Memory page has hardware error\0"
	"\0"
	"\0"
	"EPERM\0"
	"ENOENT\0"
	"ESRCH\0"
	"EINTR\0"
	"EIO\0"
	"ENXIO\0"
	"E2BIG\0"
	"ENOEXEC\0"
	"EBADF\0"
	"ECHILD\0"
	"EAGAIN\0"
	"ENOMEM\0"
	"EACCES\0"
	"EFAULT\0"
	"ENOTBLK\0"
	"EBUSY\0"
	"EEXIST\0"
	"EXDEV\0"
	"ENODEV\0"
	"ENOTDIR\0"
	"EISDIR\0"
	"EINVAL\0"
	"ENFILE\0"
	"EMFILE\0"
	"ENOTTY\0"
	"ETXTBSY\0"
	"EFBIG\0"
	"ENOSPC\0"
	"ESPIPE\0"
	"EROFS\0"
	"EMLINK\0"
	"EPIPE\0"
	"EDOM\0"
	"ERANGE\0"
	"EDEADLK\0"
	"ENAMETOOLONG\0"
	"ENOLCK\0"
	"ENOSYS\0"
	"ENOTEMPTY\0"
	"ELOOP\0"
	"ENOMSG\0"
	"EIDRM\0"
	"ECHRNG\0"
	"EL2NSYNC\0"
	"EL3HLT\0"
	"EL3RST\0"
	"ELNRNG\0"
	"EUNATCH\0"
	"ENOCSI\0"
	"EL2HLT\0"
	"EBADE\0"
	"EBADR\0"
	"EXFULL\0"
	"ENOANO\0"
	"EBADRQC\0"
	"EBADSLT\0"
	"EBFONT\0"
	"ENOSTR\0"
	"ENODATA\0"
	"ETIME\0"
	"ENOSR\0"
	"ENONET\0"
	"ENOPKG\0"
	"EREMOTE\0"
	"ENOLINK\0"
	"EADV\0"
	"ESRMNT\0"
	"ECOMM\0"
	"EPROTO\0"
	"EMULTIHOP\0"
	"EDOTDOT\0"
	"EBADMSG\0"
	"EOVERFLOW\0"
	"ENOTUNIQ\0"
	"EBADFD\0"
	"EREMCHG\0"
	"ELIBACC\0"
	"ELIBBAD\0"
	"ELIBSCN\0"
	"ELIBMAX\0"
	"ELIBEXEC\0"
	"EILSEQ\0"
	"ERESTART\0"
	"ESTRPIPE\0"
	"EUSERS\0"
	"ENOTSOCK\0"
	"EDESTADDRREQ\0"
	"EMSGSIZE\0"
	"EPROTOTYPE\0"
	"ENOPROTOOPT\0"
	"EPROTONOSUPPORT\0"
	"ESOCKTNOSUPPORT\0"
	"EOPNOTSUPP\0"
	"EPFNOSUPPORT\0"
	"EAFNOSUPPORT\0"
	"EADDRINUSE\0"
	"EADDRNOTAVAIL\0"
	"ENETDOWN\0"
	"ENETUNREACH\0"
	"ENETRESET\0"
	"ECONNABORTED\0"
	"ECONNRESET\0"
	"ENOBUFS\0"
	"EISCONN\0"
	"ENOTCONN\0"
	"ESHUTDOWN\0"
	"ETOOMANYREFS\0"
	"ETIMEDOUT\0"
	"ECONNREFUSED\0"
	"EHOSTDOWN\0"
	"EHOSTUNREACH\0"
	"EALREADY\0"
	"EINPROGRESS\0"
	"ESTALE\0"
	"EUCLEAN\0"
	"ENOTNAM\0"
	"ENAVAIL\0"
	"EISNAM\0"
	"EREMOTEIO\0"
	"EDQUOT\0"
	"ENOMEDIUM\0"
	"EMEDIUMTYPE\0"
	"ECANCELED\0"
	"ENOKEY\0"
	"EKEYEXPIRED\0"
	"EKEYREVOKED\0"
	"EKEYREJECTED\0"
	"EOWNERDEAD\0"
	"ENOTRECOVERABLE\0"
	"ERFKILL\0"
	"EHWPOISON";

static const int elu_internal_error_description_offset_table[ELU_INTERNAL_ERROR_OFFSET_TABLE_LENGTH] = {
	14, 23, 47, 73, 89, 113, 123, 149, 167, 185, 201, 220, 230, 244, 262, 274,
	296, 320, 332, 350, 365, 381, 396, 413, 433, 453, 470, 485, 500, 524, 537, 559,
	574, 586, 626, 656, 686, 705, 731, 756, 776, 0, 812, 839, 858, 886, 911, 926,
	940, 965, 994, 1021, 1036, 1053, 1080, 1094, 1103, 1124, 0, 1137, 1158, 1178, 1196, 1210,
	1235, 1265, 1287, 1304, 1326, 1342, 1356, 1384, 1399, 1418, 1437, 1456, 1494, 1521, 1550, 1573,
	1612, 1649, 1675, 1723, 1764, 1786, 1830, 1849, 1864, 1895, 1924, 1941, 1972, 1995, 2018, 2044,
	2090, 2120, 2161, 2184, 2216, 2232, 2255, 2299, 2332, 2357, 2383, 2423, 2459, 2505, 2525, 2546,
	2565, 2578, 2595, 2625, 2651, 2673, 2698, 2726, 2756, 2777, 2794, 2809, 2825, 2843, 2862, 2889,
	2905, 2926, 2954, 2965, 2987, 3025 };

static const int elu_internal_error_name_offset_table[ELU_INTERNAL_ERROR_OFFSET_TABLE_LENGTH] = {
	3057, 3058, 3064, 3071, 3077, 3083, 3087, 3093, 3099, 3107, 3113, 3120, 3127, 3134, 3141, 3148,
	3156, 3162, 3169, 3175, 3182, 3190, 3197, 3204, 3211, 3218, 3225, 3233, 3239, 3246, 3253, 3259,
	3266, 3272, 3277, 3284, 3292, 3305, 3312, 3319, 3329, 4165, 3335, 3342, 3348, 3355, 3364, 3371,
	3378, 3385, 3393, 3400, 3407, 3413, 3419, 3426, 3433, 3441, 4165, 3449, 3456, 3463, 3471, 3477,
	3483, 3490, 3497, 3505, 3513, 3518, 3525, 3531, 3538, 3548, 3556, 3564, 3574, 3583, 3590, 3598,
	3606, 3614, 3622, 3630, 3639, 3646, 3655, 3664, 3671, 3680, 3693, 3702, 3713, 3725, 3741, 3757,
	3768, 3781, 3794, 3805, 3819, 3828, 3840, 3850, 3863, 3874, 3882, 3890, 3899, 3909, 3922, 3932,
	3945, 3955, 3968, 3977, 3989, 3996, 4004, 4012, 4020, 4027, 4037, 4044, 4054, 4066, 4076, 4083,
	4095, 4107, 4120, 4131, 4147, 4155 };

#else
#error Unsupported platform
#endif

int elu_get_error_description(int error, size_t* length_address, const char** description_address)
{
	const char* description = (error > -1 && error < ELU_INTERNAL_ERROR_OFFSET_TABLE_LENGTH) ? (elu_internal_error_string_pool + elu_internal_error_description_offset_table[error]) : (elu_internal_error_string_pool + ELU_INTERNAL_UNKNOWN_ERROR_DESCRIPTION_OFFSET);
	size_t length = 0;
	while (description[length])
		++length;
	*length_address = length;
	*description_address = description;
	return 1;
}

int elu_get_error_name(int error, size_t* length_address, const char** name_address)
{
	const char* name = (error > -1 && error < ELU_INTERNAL_ERROR_OFFSET_TABLE_LENGTH) ? (elu_internal_error_string_pool + elu_internal_error_name_offset_table[error]) : (elu_internal_error_string_pool + ELU_INTERNAL_UNKNOWN_ERROR_NAME_OFFSET);
	size_t length = 0;
	while (name[length])
		++length;
	*length_address = length;
	*name_address = name;
	return 1;
}

#ifdef __cplusplus
}
#endif // __cplusplus
