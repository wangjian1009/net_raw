#include "cpe/pal/pal_string.h"
#include "net_schedule.h"
#include "net_driver.h"
#include "net_ipset.h"
#include "net_timer.h"
#include "net_tun_driver_i.h"
#include "net_tun_device_i.h"
#include "net_tun_endpoint.h"
#include "net_tun_dgram.h"
#include "net_tun_acceptor_i.h"

static int net_tun_driver_init(net_driver_t driver);
static void net_tun_driver_fini(net_driver_t driver);
#if NET_TUN_USE_EV
static void net_tun_driver_tcp_timer_cb(EV_P_ ev_timer *watcher, int revents);
#else
static void net_tun_driver_tcp_timer_cb(net_timer_t timer, void * ctx);
#endif

net_tun_driver_t
net_tun_driver_create(
    net_schedule_t schedule
#if NET_TUN_USE_EV
    , void * ev_loop
#endif
    )
{
    net_driver_t base_driver;

    base_driver = net_driver_create(
        schedule,
        "raw",
        /*driver*/
        sizeof(struct net_tun_driver),
        net_tun_driver_init,
        net_tun_driver_fini,
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
        net_tun_endpoint_connect,
        net_tun_endpoint_close,
        net_tun_endpoint_on_output,
        /*dgram*/
        sizeof(struct net_tun_dgram),
        net_tun_dgram_init,
        net_tun_dgram_fini,
        net_tun_dgram_send);

    if (base_driver == NULL) return NULL;

    net_tun_driver_t driver = net_driver_data(base_driver);

#if NET_TUN_USE_EV
    driver->m_ev_loop = ev_loop;
    ev_timer_start(driver->m_ev_loop, &driver->m_tcp_timer);
#else
    net_timer_active(driver->m_tcp_timer, TCP_TMR_INTERVAL);
#endif

    lwip_init();
    
    return net_driver_data(base_driver);
}

net_tun_driver_t net_tun_driver_cast(net_driver_t driver) {
    return strcmp(net_driver_name(driver), "raw") == 0 ? net_driver_data(driver) : NULL;
}

static int net_tun_driver_init(net_driver_t base_driver) {
    net_schedule_t schedule = net_driver_schedule(base_driver);
    net_tun_driver_t driver = net_driver_data(base_driver);

    driver->m_alloc = net_schedule_allocrator(schedule);
    driver->m_em = net_schedule_em(schedule);
#if NET_TUN_USE_EV
    driver->m_ev_loop = NULL;
#endif    
    driver->m_ipset = NULL;
    TAILQ_INIT(&driver->m_devices);
    driver->m_sock_process_fun = NULL;
    driver->m_sock_process_ctx = NULL;
    driver->m_data_monitor_fun = NULL;
    driver->m_data_monitor_ctx = NULL;
    driver->m_debug = 0;

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
    
#if NET_TUN_USE_EV
    double tcp_timer_interval = ((double)TCP_TMR_INTERVAL / 1000.0);
    ev_timer_init(&driver->m_tcp_timer, net_tun_driver_tcp_timer_cb, tcp_timer_interval, tcp_timer_interval);
#else
    driver->m_tcp_timer = net_timer_auto_create(schedule, net_tun_driver_tcp_timer_cb, driver);
#endif

    mem_buffer_init(&driver->m_data_buffer, driver->m_alloc);
    
    return 0;
}

static void net_tun_driver_fini(net_driver_t base_driver) {
    net_tun_driver_t driver = net_driver_data(base_driver);

#if NET_TUN_USE_EV
    ev_timer_stop(driver->m_ev_loop, &driver->m_tcp_timer);
#else
    net_timer_free(driver->m_tcp_timer);
    driver->m_tcp_timer = NULL;
#endif

    net_tun_acceptor_free_all(driver);
    cpe_hash_table_fini(&driver->m_acceptors);
                        
    while(!TAILQ_EMPTY(&driver->m_devices)) {
        net_tun_device_free(TAILQ_FIRST(&driver->m_devices));
    }

    if (driver->m_ipset) {
        net_ipset_free(driver->m_ipset);
    }

    mem_buffer_clear(&driver->m_data_buffer);
}

void net_tun_driver_free(net_tun_driver_t driver) {
    net_driver_free(net_driver_from_data(driver));
}

net_ipset_t net_tun_driver_ipset(net_tun_driver_t driver) {
    return driver->m_ipset;
}

net_ipset_t net_tun_driver_ipset_check_create(net_tun_driver_t driver) {
    if (driver->m_ipset == NULL) {
        driver->m_ipset = net_ipset_create(net_tun_driver_schedule(driver));
        if (driver->m_ipset == NULL) {
            CPE_ERROR(driver->m_em, "tun: driver create ipset fail!");
            return NULL;
        }
    }

    return driver->m_ipset;
}

uint8_t net_tun_driver_debug(net_tun_driver_t driver) {
    return driver->m_debug;
}

void net_tun_driver_set_debug(net_tun_driver_t driver, uint8_t debug) {
    driver->m_debug = debug;
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

#if NET_TUN_USE_EV

static void net_tun_driver_tcp_timer_cb(EV_P_ ev_timer *watcher, int revents) {
    tcp_tmr();
    return;
}

#else

static void net_tun_driver_tcp_timer_cb(net_timer_t timer, void * ctx) {
    tcp_tmr();
    net_timer_active(timer, TCP_TMR_INTERVAL);
}

#endif
