#include "cpe/pal/pal_time.h"
#include <lwip/sys.h>

u32_t sys_now (void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (u32_t)((int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec/1000);
}
