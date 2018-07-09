#ifndef LWIP_CUSTOM_CC_H
#define LWIP_CUSTOM_CC_H

#include <errno.h>
#include <arpa/inet.h>
#include "cpe/pal/pal_platform.h"
#include "cpe/pal/pal_stdio.h"
#include "cpe/pal/pal_stdlib.h"

#define u8_t uint8_t
#define s8_t int8_t
#define u16_t uint16_t
#define s16_t int16_t
#define u32_t uint32_t
#define s32_t int32_t
#define mem_ptr_t uintptr_t

#define PACK_STRUCT_BEGIN CPE_START_PACKED
#define PACK_STRUCT_END CPE_END_PACKED
#define PACK_STRUCT_STRUCT CPE_PACKED

#define LWIP_PLATFORM_DIAG(x) { if (BLog_WouldLog(BLOG_CHANNEL_lwip, BLOG_INFO)) { BLog_Begin(); BLog_Append x; BLog_Finish(BLOG_CHANNEL_lwip, BLOG_INFO); } }
#define LWIP_PLATFORM_ASSERT(x) { fprintf(stderr, "%s: lwip assertion failure: %s\n", __FUNCTION__, (x)); abort(); }

#define U16_F PRIu16
#define S16_F PRId16
#define X16_F PRIx16
#define U32_F PRIu32
#define S32_F PRId32
#define X32_F PRIx32
#define SZT_F "zu"

#define LWIP_PLATFORM_BYTESWAP 0
/* #define LWIP_PLATFORM_HTONS(x) hton16(x) */
/* #define LWIP_PLATFORM_HTONL(x) hton32(x) */

#define LWIP_RAND() ( \
    (((uint32_t)(rand() & 0xFF)) << 24) | \
    (((uint32_t)(rand() & 0xFF)) << 16) | \
    (((uint32_t)(rand() & 0xFF)) << 8) | \
    (((uint32_t)(rand() & 0xFF)) << 0) \
)

#include <endian.h>

#endif
