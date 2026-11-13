/*
 * vmsnotify tests, from vmsotel's tests/q.h: vn_u64 to and from unsigned long long.
 *
 * vn_u64 is opaque (vn_types.h): two longwords under VN_SOFT64, as on
 * VAX. The tests run only on Linux, where unsigned long long exists,
 * so they build vn_u64 values with Q() and read them back with ULL().
 */

#ifndef VN_TEST_Q_H
#define VN_TEST_Q_H

#include "vn_types.h"

#define Q(v) vn_q((vn_u32) ((unsigned long long) (v) >> 32), (vn_u32) (v))
#define ULL(v) ((unsigned long long) vn_qhi(v) << 32 | vn_qlo(v))

#endif
