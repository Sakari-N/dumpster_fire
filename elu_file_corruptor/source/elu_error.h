/*
	Simple POSIX error code to text convertion API authored by archiver Sakari N.

	Description

		Simple API for translating POSIX error codes to text.

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

#ifndef ELU_ERROR_H
#define ELU_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stddef.h>

#if defined(_WIN32)

#ifndef EPERM
#define EPERM 1
#endif // EPERM
#ifndef ENOENT
#define ENOENT 2
#endif // ENOENT
#ifndef ESRCH
#define ESRCH 3
#endif // ESRCH
#ifndef EINTR
#define EINTR 4
#endif // EINTR
#ifndef EIO
#define EIO 5
#endif // EIO
#ifndef ENXIO
#define ENXIO 6
#endif // ENXIO
#ifndef E2BIG
#define E2BIG 7
#endif // E2BIG
#ifndef ENOEXEC
#define ENOEXEC 8
#endif // ENOEXEC
#ifndef EBADF
#define EBADF 9
#endif // EBADF
#ifndef ECHILD
#define ECHILD 10
#endif // ECHILD
#ifndef EAGAIN
#define EAGAIN 11
#endif // EAGAIN
#ifndef ENOMEM
#define ENOMEM 12
#endif // ENOMEM
#ifndef EACCES
#define EACCES 13
#endif // EACCES
#ifndef EFAULT
#define EFAULT 14
#endif // EFAULT
#ifndef ENOTBLK
#define ENOTBLK 15
#endif // ENOTBLK
#ifndef EBUSY
#define EBUSY 16
#endif // EBUSY
#ifndef EEXIST
#define EEXIST 17
#endif // EEXIST
#ifndef EXDEV
#define EXDEV 18
#endif // EXDEV
#ifndef ENODEV
#define ENODEV 19
#endif // ENODEV
#ifndef ENOTDIR
#define ENOTDIR 20
#endif // ENOTDIR
#ifndef EISDIR
#define EISDIR 21
#endif // EISDIR
#ifndef EINVAL
#define EINVAL 22
#endif // EINVAL
#ifndef ENFILE
#define ENFILE 23
#endif // ENFILE
#ifndef EMFILE
#define EMFILE 24
#endif // EMFILE
#ifndef ENOTTY
#define ENOTTY 25
#endif // ENOTTY
#ifndef EFBIG
#define EFBIG 27
#endif // EFBIG
#ifndef ENOSPC
#define ENOSPC 28
#endif // ENOSPC
#ifndef ESPIPE
#define ESPIPE 29
#endif // ESPIPE
#ifndef EROFS
#define EROFS 30
#endif // EROFS
#ifndef EMLINK
#define EMLINK 31
#endif // EMLINK
#ifndef EPIPE
#define EPIPE 32
#endif // EPIPE
#ifndef EDOM
#define EDOM 33
#endif // EDOM
#ifndef ERANGE
#define ERANGE 34
#endif // ERANGE
#ifndef EDEADLK
#define EDEADLK 36
#endif // EDEADLK
#ifndef ENAMETOOLONG
#define ENAMETOOLONG 38
#endif // ENAMETOOLONG
#ifndef ENOLCK
#define ENOLCK 39
#endif // ENOLCK
#ifndef ENOSYS
#define ENOSYS 40
#endif // ENOSYS
#ifndef ENOTEMPTY
#define ENOTEMPTY 41
#endif // ENOTEMPTY
#ifndef EILSEQ
#define EILSEQ 42
#endif // EILSEQ
#ifndef EADDRINUSE
#define EADDRINUSE 100
#endif // EADDRINUSE
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL 101
#endif // EADDRNOTAVAIL
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT 102
#endif // EAFNOSUPPORT
#ifndef EALREADY
#define EALREADY 103
#endif // EALREADY
#ifndef EBADMSG
#define EBADMSG 104
#endif // EBADMSG
#ifndef ECANCELED
#define ECANCELED 105
#endif // ECANCELED
#ifndef ECONNABORTED
#define ECONNABORTED 106
#endif // ECONNABORTED
#ifndef ECONNREFUSED
#define ECONNREFUSED 107
#endif // ECONNREFUSED
#ifndef ECONNRESET
#define ECONNRESET 108
#endif // ECONNRESET
#ifndef EDESTADDRREQ
#define EDESTADDRREQ 109
#endif // EDESTADDRREQ
#ifndef EHOSTUNREACH
#define EHOSTUNREACH 110
#endif // EHOSTUNREACH
#ifndef EIDRM
#define EIDRM 111
#endif // EIDRM
#ifndef EINPROGRESS
#define EINPROGRESS 112
#endif // EINPROGRESS
#ifndef EISCONN
#define EISCONN 113
#endif // EISCONN
#ifndef ELOOP
#define ELOOP 114
#endif // ELOOP
#ifndef EMSGSIZE
#define EMSGSIZE 115
#endif // EMSGSIZE
#ifndef ENETDOWN
#define ENETDOWN 116
#endif // ENETDOWN
#ifndef ENETRESET
#define ENETRESET 117
#endif // ENETRESET
#ifndef ENETUNREACH
#define ENETUNREACH 118
#endif // ENETUNREACH
#ifndef ENOBUFS
#define ENOBUFS 119
#endif // ENOBUFS
#ifndef ENODATA
#define ENODATA 120
#endif // ENODATA
#ifndef ENOLINK
#define ENOLINK 121
#endif // ENOLINK
#ifndef ENOMSG
#define ENOMSG 122
#endif // ENOMSG
#ifndef ENOPROTOOPT
#define ENOPROTOOPT 123
#endif // ENOPROTOOPT
#ifndef ENOSR
#define ENOSR 124
#endif // ENOSR
#ifndef ENOSTR
#define ENOSTR 125
#endif // ENOSTR
#ifndef ENOTCONN
#define ENOTCONN 126
#endif // ENOTCONN
#ifndef ENOTRECOVERABLE
#define ENOTRECOVERABLE 127
#endif // ENOTRECOVERABLE
#ifndef ENOTSOCK
#define ENOTSOCK 128
#endif // ENOTSOCK
#ifndef ENOTSUP
#define ENOTSUP 129
#endif // ENOTSUP
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 130
#endif // EOPNOTSUPP
#ifndef EOTHER
#define EOTHER 131
#endif // EOTHER
#ifndef EOVERFLOW
#define EOVERFLOW 132
#endif // EOVERFLOW
#ifndef EOWNERDEAD
#define EOWNERDEAD 133
#endif // EOWNERDEAD
#ifndef EPROTO
#define EPROTO 134
#endif // EPROTO
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT 135
#endif // EPROTONOSUPPORT
#ifndef EPROTOTYPE
#define EPROTOTYPE 136
#endif // EPROTOTYPE
#ifndef ETIME
#define ETIME 137
#endif // ETIME
#ifndef ETIMEDOUT
#define ETIMEDOUT 138
#endif // ETIMEDOUT
#ifndef ETXTBSY
#define ETXTBSY 139
#endif // ETXTBSY
#ifndef EWOULDBLOCK
#define EWOULDBLOCK 140
#endif // EWOULDBLOCK

#elif defined(__linux__) || defined(linux) || defined(__linux)

#ifndef EPERM
#define EPERM 1
#endif // EPERM
#ifndef ENOENT
#define ENOENT 2
#endif // ENOENT
#ifndef ESRCH
#define ESRCH 3
#endif // ESRCH
#ifndef EINTR
#define EINTR 4
#endif // EINTR
#ifndef EIO
#define EIO 5
#endif // EIO
#ifndef ENXIO
#define ENXIO 6
#endif // ENXIO
#ifndef E2BIG
#define E2BIG 7
#endif // E2BIG
#ifndef ENOEXEC
#define ENOEXEC 8
#endif // ENOEXEC
#ifndef EBADF
#define EBADF 9
#endif // EBADF
#ifndef ECHILD
#define ECHILD 10
#endif // ECHILD
#ifndef EAGAIN
#define EAGAIN 11
#endif // EAGAIN
#ifndef ENOMEM
#define ENOMEM 12
#endif // ENOMEM
#ifndef EACCES
#define EACCES 13
#endif // EACCES
#ifndef EFAULT
#define EFAULT 14
#endif // EFAULT
#ifndef ENOTBLK
#define ENOTBLK 15
#endif // ENOTBLK
#ifndef EBUSY
#define EBUSY 16
#endif // EBUSY
#ifndef EEXIST
#define EEXIST 17
#endif // EEXIST
#ifndef EXDEV
#define EXDEV 18
#endif // EXDEV
#ifndef ENODEV
#define ENODEV 19
#endif // ENODEV
#ifndef ENOTDIR
#define ENOTDIR 20
#endif // ENOTDIR
#ifndef EISDIR
#define EISDIR 21
#endif // EISDIR
#ifndef EINVAL
#define EINVAL 22
#endif // EINVAL
#ifndef ENFILE
#define ENFILE 23
#endif // ENFILE
#ifndef EMFILE
#define EMFILE 24
#endif // EMFILE
#ifndef ENOTTY
#define ENOTTY 25
#endif // ENOTTY
#ifndef ETXTBSY
#define ETXTBSY 26
#endif // ETXTBSY
#ifndef EFBIG
#define EFBIG 27
#endif // EFBIG
#ifndef ENOSPC
#define ENOSPC 28
#endif // ENOSPC
#ifndef ESPIPE
#define ESPIPE 29
#endif // ESPIPE
#ifndef EROFS
#define EROFS 30
#endif // EROFS
#ifndef EMLINK
#define EMLINK 31
#endif // EMLINK
#ifndef EPIPE
#define EPIPE 32
#endif // EPIPE
#ifndef EDOM
#define EDOM 33
#endif // EDOM
#ifndef ERANGE
#define ERANGE 34
#endif // ERANGE
#ifndef EDEADLK
#define EDEADLK 35
#endif // EDEADLK
#ifndef ENAMETOOLONG
#define ENAMETOOLONG 36
#endif // ENAMETOOLONG
#ifndef ENOLCK
#define ENOLCK 37
#endif // ENOLCK
#ifndef ENOSYS
#define ENOSYS 38
#endif // ENOSYS
#ifndef ENOTEMPTY
#define ENOTEMPTY 39
#endif // ENOTEMPTY
#ifndef ELOOP
#define ELOOP 40
#endif // ELOOP
#ifndef ENOMSG
#define ENOMSG 42
#endif // ENOMSG
#ifndef EIDRM
#define EIDRM 43
#endif // EIDRM
#ifndef ECHRNG
#define ECHRNG 44
#endif // ECHRNG
#ifndef EL2NSYNC
#define EL2NSYNC 45
#endif // EL2NSYNC
#ifndef EL3HLT
#define EL3HLT 46
#endif // EL3HLT
#ifndef EL3RST
#define EL3RST 47
#endif // EL3RST
#ifndef ELNRNG
#define ELNRNG 48
#endif // ELNRNG
#ifndef EUNATCH
#define EUNATCH 49
#endif // EUNATCH
#ifndef ENOCSI
#define ENOCSI 50
#endif // ENOCSI
#ifndef EL2HLT
#define EL2HLT 51
#endif // EL2HLT
#ifndef EBADE
#define EBADE 52
#endif // EBADE
#ifndef EBADR
#define EBADR 53
#endif // EBADR
#ifndef EXFULL
#define EXFULL 54
#endif // EXFULL
#ifndef ENOANO
#define ENOANO 55
#endif // ENOANO
#ifndef EBADRQC
#define EBADRQC 56
#endif // EBADRQC
#ifndef EBADSLT
#define EBADSLT 57
#endif // EBADSLT
#ifndef EBFONT
#define EBFONT 59
#endif // EBFONT
#ifndef ENOSTR
#define ENOSTR 60
#endif // ENOSTR
#ifndef ENODATA
#define ENODATA 61
#endif // ENODATA
#ifndef ETIME
#define ETIME 62
#endif // ETIME
#ifndef ENOSR
#define ENOSR 63
#endif // ENOSR
#ifndef ENONET
#define ENONET 64
#endif // ENONET
#ifndef ENOPKG
#define ENOPKG 65
#endif // ENOPKG
#ifndef EREMOTE
#define EREMOTE 66
#endif // EREMOTE
#ifndef ENOLINK
#define ENOLINK 67
#endif // ENOLINK
#ifndef EADV
#define EADV 68
#endif // EADV
#ifndef ESRMNT
#define ESRMNT 69
#endif // ESRMNT
#ifndef ECOMM
#define ECOMM 70
#endif // ECOMM
#ifndef EPROTO
#define EPROTO 71
#endif // EPROTO
#ifndef EMULTIHOP
#define EMULTIHOP 72
#endif // EMULTIHOP
#ifndef EDOTDOT
#define EDOTDOT 73
#endif // EDOTDOT
#ifndef EBADMSG
#define EBADMSG 74
#endif // EBADMSG
#ifndef EOVERFLOW
#define EOVERFLOW 75
#endif // EOVERFLOW
#ifndef ENOTUNIQ
#define ENOTUNIQ 76
#endif // ENOTUNIQ
#ifndef EBADFD
#define EBADFD 77
#endif // EBADFD
#ifndef EREMCHG
#define EREMCHG 78
#endif // EREMCHG
#ifndef ELIBACC
#define ELIBACC 79
#endif // ELIBACC
#ifndef ELIBBAD
#define ELIBBAD 80
#endif // ELIBBAD
#ifndef ELIBSCN
#define ELIBSCN 81
#endif // ELIBSCN
#ifndef ELIBMAX
#define ELIBMAX 82
#endif // ELIBMAX
#ifndef ELIBEXEC
#define ELIBEXEC 83
#endif // ELIBEXEC
#ifndef EILSEQ
#define EILSEQ 84
#endif // EILSEQ
#ifndef ERESTART
#define ERESTART 85
#endif // ERESTART
#ifndef ESTRPIPE
#define ESTRPIPE 86
#endif // ESTRPIPE
#ifndef EUSERS
#define EUSERS 87
#endif // EUSERS
#ifndef ENOTSOCK
#define ENOTSOCK 88
#endif // ENOTSOCK
#ifndef EDESTADDRREQ
#define EDESTADDRREQ 89
#endif // EDESTADDRREQ
#ifndef EMSGSIZE
#define EMSGSIZE 90
#endif // EMSGSIZE
#ifndef EPROTOTYPE
#define EPROTOTYPE 91
#endif // EPROTOTYPE
#ifndef ENOPROTOOPT
#define ENOPROTOOPT 92
#endif // ENOPROTOOPT
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT 93
#endif // EPROTONOSUPPORT
#ifndef ESOCKTNOSUPPORT
#define ESOCKTNOSUPPORT 94
#endif // ESOCKTNOSUPPORT
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif // EOPNOTSUPP
#ifndef EPFNOSUPPORT
#define EPFNOSUPPORT 96
#endif // EPFNOSUPPORT
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT 97
#endif // EAFNOSUPPORT
#ifndef EADDRINUSE
#define EADDRINUSE 98
#endif // EADDRINUSE
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL 99
#endif // EADDRNOTAVAIL
#ifndef ENETDOWN
#define ENETDOWN 100
#endif // ENETDOWN
#ifndef ENETUNREACH
#define ENETUNREACH 101
#endif // ENETUNREACH
#ifndef ENETRESET
#define ENETRESET 102
#endif // ENETRESET
#ifndef ECONNABORTED
#define ECONNABORTED 103
#endif // ECONNABORTED
#ifndef ECONNRESET
#define ECONNRESET 104
#endif // ECONNRESET
#ifndef ENOBUFS
#define ENOBUFS 105
#endif // ENOBUFS
#ifndef EISCONN
#define EISCONN 106
#endif // EISCONN
#ifndef ENOTCONN
#define ENOTCONN 107
#endif // ENOTCONN
#ifndef ESHUTDOWN
#define ESHUTDOWN 108
#endif // ESHUTDOWN
#ifndef ETOOMANYREFS
#define ETOOMANYREFS 109
#endif // ETOOMANYREFS
#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif // ETIMEDOUT
#ifndef ECONNREFUSED
#define ECONNREFUSED 111
#endif // ECONNREFUSED
#ifndef EHOSTDOWN
#define EHOSTDOWN 112
#endif // EHOSTDOWN
#ifndef EHOSTUNREACH
#define EHOSTUNREACH 113
#endif // EHOSTUNREACH
#ifndef EALREADY
#define EALREADY 114
#endif // EALREADY
#ifndef EINPROGRESS
#define EINPROGRESS 115
#endif // EINPROGRESS
#ifndef ESTALE
#define ESTALE 116
#endif // ESTALE
#ifndef EUCLEAN
#define EUCLEAN 117
#endif // EUCLEAN
#ifndef ENOTNAM
#define ENOTNAM 118
#endif // ENOTNAM
#ifndef ENAVAIL
#define ENAVAIL 119
#endif // ENAVAIL
#ifndef EISNAM
#define EISNAM 120
#endif // EISNAM
#ifndef EREMOTEIO
#define EREMOTEIO 121
#endif // EREMOTEIO
#ifndef EDQUOT
#define EDQUOT 122
#endif // EDQUOT
#ifndef ENOMEDIUM
#define ENOMEDIUM 123
#endif // ENOMEDIUM
#ifndef EMEDIUMTYPE
#define EMEDIUMTYPE 124
#endif // EMEDIUMTYPE
#ifndef ECANCELED
#define ECANCELED 125
#endif // ECANCELED
#ifndef ENOKEY
#define ENOKEY 126
#endif // ENOKEY
#ifndef EKEYEXPIRED
#define EKEYEXPIRED 127
#endif // EKEYEXPIRED
#ifndef EKEYREVOKED
#define EKEYREVOKED 128
#endif // EKEYREVOKED
#ifndef EKEYREJECTED
#define EKEYREJECTED 129
#endif // EKEYREJECTED
#ifndef EOWNERDEAD
#define EOWNERDEAD 130
#endif // EOWNERDEAD
#ifndef ENOTRECOVERABLE
#define ENOTRECOVERABLE 131
#endif // ENOTRECOVERABLE
#ifndef ERFKILL
#define ERFKILL 132
#endif // ERFKILL
#ifndef EHWPOISON
#define EHWPOISON 133
#endif // EHWPOISON

#else
#error Unsupported platform
#endif

int elu_get_error_description(int error, size_t* length_address, const char** description_address);

int elu_get_error_name(int error, size_t* length_address, const char** name_address);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // ELU_ERROR_H
