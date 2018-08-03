#include "cpe/utils/error.h"
#include "arch/cc.h"

error_monitor_t g_lwip_em = NULL;

void lwip_em_info_printf(const char * fmt, ...) {
    va_list args;

    if (g_lwip_em) {
        g_lwip_em->m_curent_location.m_errno = 0;
        g_lwip_em->m_curent_location.m_level = CPE_EL_INFO;
        va_start(args, fmt);
        cpe_error_do_notify_var(g_lwip_em, fmt, args);
        va_end(args);
    }
}

void lwip_em_error_printf(const char * fmt, ...) {
    va_list args;
    if (g_lwip_em) {
        g_lwip_em->m_curent_location.m_errno = 0;
        g_lwip_em->m_curent_location.m_level = CPE_EL_ERROR;
        va_start(args, fmt);
        cpe_error_do_notify_var(g_lwip_em, fmt, args);
        va_end(args);
    }
}    
