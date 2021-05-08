#include <assert.h>
#include "cpe/pal/pal_string.h"
#include "lwip/nd6.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_frag.h"
#include "net_schedule.h"
#include "net_driver.h"
#include "net_timer.h"
#include "net_address.h"
#include "net_tun_driver_i.h"
#include "net_tun_device_i.h"
#include "net_tun_endpoint.h"
#include "net_tun_dgram.h"
#include "net_tun_acceptor_i.h"
#include "net_tun_wildcard_acceptor_i.h"
#include "net_tun_utils.h"

static int net_tun_driver_init(net_driver_t driver);
static void net_tun_driver_fini(net_driver_t driver);
#if NET_TUN_USE_DRIVER
static void net_tun_driver_tcp_timer_cb(net_timer_t timer, void * ctx);
#endif

net_tun_driver_t
net_tun_driver_create(
    net_schedule_t schedule
#if NET_TUN_USE_DRIVER
    , net_driver_t inner_driver
#endif
    )
{
    net_driver_t base_driver;

    base_driver = net_driver_create(
        schedule,
        "tun",
        /*driver*/
        sizeof(struct net_tun_driver),
        net_tun_driver_init,
        net_tun_driver_fini,
        NULL,
        /*timer*/
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        /*acceptor*/
        0,
        NULL,
        NULL,
        /*endpoint*/
        sizeof(struct net_tun_endpoint),
        net_tun_endpoint_init,
        net_tun_endpoint_fini,
        net_tun_endpoint_calc_size,
        net_tun_endpoint_connect,
        net_tun_endpoint_update,
        net_tun_endpoint_set_no_delay,
        net_tun_endpoint_get_mss,
        /*dgram*/
        sizeof(struct net_tun_dgram),
        net_tun_dgram_init,
        net_tun_dgram_fini,
        net_tun_dgram_send,
        /*watcher*/
        0, NULL, NULL, NULL,
        /*progress*/
        0, NULL, NULL);

    if (base_driver == NULL) return NULL;

    net_tun_driver_t driver = net_driver_data(base_driver);

#if NET_TUN_USE_DRIVER
    driver->m_inner_driver = inner_driver;

    driver->m_tcp_timer = net_timer_create(inner_driver, net_tun_driver_tcp_timer_cb, driver);
    if (driver->m_tcp_timer == NULL) {
        net_driver_free(base_driver);
        return NULL;
    }
    net_timer_active(driver->m_tcp_timer, TCP_TMR_INTERVAL);
#endif

    g_lwip_em = driver->m_em;
    lwip_init();
    
    return driver;
}

net_tun_driver_t net_tun_driver_find(net_schedule_t schedule) {
    net_driver_t driver = net_driver_find(schedule, "tun");
    return driver ? net_tun_driver_cast(driver) : NULL;
}

net_tun_driver_t net_tun_driver_cast(net_driver_t base_driver) {
    return strcmp(net_driver_name(base_driver), "tun") == 0 ? net_driver_data(base_driver) : NULL;
}

net_driver_t net_tun_driver_base_driver(net_tun_driver_t driver) {
    return net_driver_from_data(driver);
}

static int net_tun_driver_init(net_driver_t base_driver) {
    net_schedule_t schedule = net_driver_schedule(base_driver);
    net_tun_driver_t driver = net_driver_data(base_driver);

    driver->m_alloc = net_schedule_allocrator(schedule);
    driver->m_em = net_schedule_em(schedule);
#if NET_TUN_USE_DRIVER
    driver->m_inner_driver = NULL;
    driver->m_tcp_timer = NULL;
#endif    
    driver->m_tcp_timer_counter = 0;

    TAILQ_INIT(&driver->m_devices);
    TAILQ_INIT(&driver->m_wildcard_acceptors);

    driver->m_sock_process_fun = NULL;
    driver->m_sock_process_ctx = NULL;
    driver->m_data_monitor_fun = NULL;
    driver->m_data_monitor_ctx = NULL;
    driver->m_default_device = NULL;

    if (cpe_hash_table_init(
            &driver->m_acceptors,
            driver->m_alloc,
            (cpe_hash_fun_t) net_tun_acceptor_hash,
            (cpe_hash_eq_t) net_tun_acceptor_eq,
            CPE_HASH_OBJ2ENTRY(net_tun_acceptor, m_hh),
            -1) != 0)
    {
        return -1;
    }

#if NET_TUN_USE_DQ
    driver->m_tcp_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_retain(driver->m_tcp_timer);
    dispatch_source_set_event_handler(driver->m_tcp_timer, ^{ net_tun_dirver_do_timer(driver); });
    uint64_t tcp_timer_interval = ((uint64_t)TCP_TMR_INTERVAL) * 1000000u;
    dispatch_source_set_timer(
        driver->m_tcp_timer,
        dispatch_time(DISPATCH_TIME_NOW, tcp_timer_interval),
        tcp_timer_interval,
        0ULL);
    dispatch_resume(driver->m_tcp_timer);
#endif

    mem_buffer_init(&driver->m_data_buffer, driver->m_alloc);
    
    return 0;
}

static void net_tun_driver_fini(net_driver_t base_driver) {
    net_tun_driver_t driver = net_driver_data(base_driver);

#if NET_TUN_USE_DRIVER
    if (driver->m_tcp_timer) {
        net_timer_free(driver->m_tcp_timer);
        driver->m_tcp_timer = NULL;
    }
#endif

#if NET_TUN_USE_DQ
    dispatch_source_set_event_handler(driver->m_tcp_timer, nil);
    dispatch_source_cancel(driver->m_tcp_timer);
    dispatch_release(driver->m_tcp_timer);
    driver->m_tcp_timer = nil;
#endif

    net_tun_acceptor_free_all(driver);
    cpe_hash_table_fini(&driver->m_acceptors);

    while(!TAILQ_EMPTY(&driver->m_wildcard_acceptors)) {
        net_tun_wildcard_acceptor_free(TAILQ_FIRST(&driver->m_wildcard_acceptors));
    }

    while(!TAILQ_EMPTY(&driver->m_devices)) {
        net_tun_device_free(TAILQ_FIRST(&driver->m_devices));
    }

    mem_buffer_clear(&driver->m_data_buffer);
}

void net_tun_driver_free(net_tun_driver_t driver) {
    net_driver_free(net_driver_from_data(driver));
}

void net_tun_driver_set_sock_create_processor(
    net_tun_driver_t driver,
    net_tun_driver_sock_create_process_fun_t process_fun,
    void * process_ctx)
{
    driver->m_sock_process_fun = process_fun;
    driver->m_sock_process_ctx = process_ctx;
}
    
void net_tun_driver_set_data_monitor(
    net_tun_driver_t driver,
    net_data_monitor_fun_t monitor_fun, void * monitor_ctx)
{
    driver->m_data_monitor_fun = monitor_fun;
    driver->m_data_monitor_ctx = monitor_ctx;
}

net_schedule_t net_tun_driver_schedule(net_tun_driver_t driver) {
    return net_driver_schedule(net_driver_from_data(driver));
}

mem_buffer_t net_tun_driver_tmp_buffer(net_tun_driver_t driver) {
    return net_schedule_tmp_buffer(net_driver_schedule(net_driver_from_data(driver)));
}

uint8_t net_tun_driver_debug(net_tun_driver_t driver) {
    return net_driver_debug(net_driver_from_data(driver));
}

#if NET_TUN_USE_DRIVER

static void net_tun_driver_tcp_timer_cb(net_timer_t timer, void * ctx) {
    net_tun_dirver_do_timer(ctx);
    net_timer_active(timer, TCP_TMR_INTERVAL);

}

void net_tun_dirver_do_timer(net_tun_driver_t driver) {
    tcp_tmr();
    
    driver->m_tcp_timer_counter = (driver->m_tcp_timer_counter + 1) % 4;
    
    // every second, call other timer functions
    if (driver->m_tcp_timer_counter == 0) {
#if IP_REASSEMBLY
        assert(IP_TMR_INTERVAL == 4 * TCP_TMR_INTERVAL);
        ip_reass_tmr();
#endif
        
#if LWIP_IPV6
        assert(ND6_TMR_INTERVAL == 4 * TCP_TMR_INTERVAL);
        nd6_tmr();
#endif
    
#if LWIP_IPV6 && LWIP_IPV6_REASS
        assert(IP6_REASS_TMR_INTERVAL == 4 * TCP_TMR_INTERVAL);
        ip6_reass_tmr();
#endif
    }
}

#endif
