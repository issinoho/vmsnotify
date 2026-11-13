/*
 * vmsnotify, from vmsotel's src/model/vo_types.h: fixed-width integer types, the 64-bit one's arithmetic, and
 * a bounded formatter.
 *
 * Not <stdint.h>: VAX has none (Compaq C V6.4), and these are certain.
 * unsigned int is 32 bits on every VMS architecture and on Linux; the
 * typedef below fails to compile if that is ever untrue (C99 has no
 * _Static_assert, so a negative array size does the job).
 *
 * vn_u64 is opaque. On VAX, whose compiler has no 64-bit integer type
 * at all (vmsotel findings, "VAX"), it is two longwords; everywhere else it is
 * unsigned long long. Code touches it only through the functions
 * below, so both build the same way, and make check builds the
 * two-longword form on Linux too (VN_SOFT64) and runs the golden
 * payloads through it.
 *
 * snprintf and vsnprintf do not exist on VAX either, so the agent uses
 * vn_snprintf and vn_vsnprintf: always NUL-terminated, never past cap,
 * returning the length that full output would have had. They know
 * flags - and 0, a width, a precision (number or *) for %s, the length
 * l, and d u x X s c %. No floating point and no long long: a vn_u64
 * goes through vn_qstr and %s.
 */

#ifndef VN_TYPES_H
#define VN_TYPES_H

#include <stdarg.h>
#include <stddef.h>

#if defined(__VAX) && !defined(VN_SOFT64)
#  define VN_SOFT64 1
#endif

typedef unsigned int vn_u32;

typedef char vn_check_u32_is_4_bytes[sizeof(vn_u32) == 4 ? 1 : -1];

#ifdef VN_SOFT64
typedef struct {
    vn_u32 lo, hi;
} vn_u64;
#else
typedef unsigned long long vn_u64;
typedef char vn_check_u64_is_8_bytes[sizeof(vn_u64) == 8 ? 1 : -1];
#endif

/* Decimal digits of 2^64 - 1, and a NUL. */
#define VN_QSTR_MAX 21

vn_u64 vn_q(vn_u32 hi, vn_u32 lo);          /* hi * 2^32 + lo */
vn_u64 vn_q32(vn_u32 v);
vn_u64 vn_qul(unsigned long v);             /* 32 bits on VMS, 64 on Linux */
vn_u32 vn_qlo(vn_u64 a);
vn_u32 vn_qhi(vn_u64 a);
int vn_qzero(vn_u64 a);
int vn_qcmp(vn_u64 a, vn_u64 b);            /* -1, 0 or 1 */
vn_u64 vn_qadd(vn_u64 a, vn_u64 b);         /* modulo 2^64 */
vn_u64 vn_qsub(vn_u64 a, vn_u64 b);         /* modulo 2^64 */
vn_u64 vn_qmul(vn_u64 a, vn_u32 m);         /* modulo 2^64 */
/* a / d, for 0 < d < 2^31; the remainder in *rem unless it is NULL. */
vn_u64 vn_qdiv(vn_u64 a, vn_u32 d, vn_u32 *rem);
/* Decimal into buf, VN_QSTR_MAX bytes at least; returns buf. */
char *vn_qstr(vn_u64 a, char *buf);
double vn_qdouble(vn_u64 a);

int vn_snprintf(char *buf, size_t cap, const char *fmt, ...);
int vn_vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap);

#endif
